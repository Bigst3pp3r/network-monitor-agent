"""
scanner.py — Network scanning: discovery, ports, OS detection.

Flow
----
1.  Self-detect the host machine (IP + MAC from /sys/class/net or ip-route)
2.  ARP ping sweep to find all live hosts on the subnet
3.  Parallel port+OS scan of every discovered device (SCAN_THREADS workers)

Host detection
--------------
Primary   : read /sys/class/net/<iface>/address  (fastest, always works in-container)
Fallback  : parse `ip link show` output
IP-match  : if MAC detection fails, mark device as host when its IP matches ours

Port scanning
-------------
Pass A (required) : nmap -sV  — returns open ports + service versions
Pass B (optional) : nmap -O   — OS fingerprint using a known-open port as hint
Both passes are independent; a failure in B never affects A's port results.
"""

import logging
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from monitor.config import NETWORK_SUBNET, PORT_SCAN_LIST, SCAN_THREADS
from monitor.oui import get_vendor

log = logging.getLogger(__name__)


@dataclass
class DeviceResult:
    mac:          str
    ip:           str
    hostname:     str
    vendor:       str
    open_ports:   list[str] = field(default_factory=list)
    os_info:      str  = ""
    os_accuracy:  int  = 0
    status:       str  = "online"
    is_host:      bool = False


# ── Utility helpers ───────────────────────────────────────────────────────────

def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _get_mac_from_arp(ip: str) -> str:
    """Read ARP cache for a given IP."""
    try:
        out = subprocess.check_output(["arp", "-n", ip], text=True, timeout=5)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and ":" in parts[2] and parts[2] != "(incomplete)":
                return parts[2].upper()
    except Exception:
        pass
    return ""


# ── Host self-detection ───────────────────────────────────────────────────────

def _get_host_ip() -> str:
    """Find this machine's LAN IP using the UDP connect trick."""
    try:
        gateway = NETWORK_SUBNET.rsplit(".", 1)[0] + ".1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((gateway, 80))
            return s.getsockname()[0]
    except Exception as e:
        log.debug("Could not determine host IP: %s", e)
        return ""


def _get_host_mac_and_iface(host_ip: str) -> tuple[str, str]:
    """
    Find MAC and interface name for host_ip.
    Tries three methods in order:
      1. /sys/class/net/<iface>/address  (most reliable in containers)
      2. ip link show output parsing
      3. ARP cache (for the host's own IP, rare but works)
    """
    # Method 1: parse `ip addr` to find the interface for host_ip
    try:
        out = subprocess.check_output(["ip", "-o", "addr", "show"],
                                      text=True, timeout=5)
        for line in out.splitlines():
            if host_ip in line:
                iface = line.split()[1]
                # Read MAC from sysfs
                try:
                    with open(f"/sys/class/net/{iface}/address") as f:
                        mac = f.read().strip().upper()
                        if mac and mac != "00:00:00:00:00:00":
                            return mac, iface
                except Exception:
                    pass
                # Fall through to ip link parsing for this iface
                break
    except Exception as e:
        log.debug("ip addr parse failed: %s", e)

    # Method 2: ip link show — find link/ether for each interface
    try:
        out   = subprocess.check_output(["ip", "link", "show"], text=True, timeout=5)
        lines = out.splitlines()
        # Find any non-loopback interface that has link/ether
        for i, line in enumerate(lines):
            if "lo" in line:
                continue
            if i + 1 < len(lines) and "link/ether" in lines[i + 1]:
                iface = line.split(":")[1].strip() if ":" in line else ""
                mac   = lines[i + 1].split()[1].upper()
                if mac and mac != "00:00:00:00:00:00":
                    return mac, iface
    except Exception as e:
        log.debug("ip link parse failed: %s", e)

    return "", ""


def get_host_device() -> DeviceResult | None:
    """Return a DeviceResult for the machine running the scanner."""
    host_ip = _get_host_ip()
    if not host_ip:
        log.warning("Host IP detection failed")
        return None

    mac, iface = _get_host_mac_and_iface(host_ip)
    if not mac:
        log.warning("Host MAC detection failed for IP %s — host will appear as regular device", host_ip)
        return None

    hostname = ""
    try:
        hostname = socket.gethostname()
    except Exception:
        pass

    vendor = get_vendor(mac)
    log.info("Host machine: mac=%s  ip=%s  vendor=%s  iface=%s",
             mac, host_ip, vendor, iface)

    return DeviceResult(
        mac=mac, ip=host_ip, hostname=hostname,
        vendor=vendor, status="online", is_host=True,
    )


# ── Per-device scan: ports + OS ───────────────────────────────────────────────

def _scan_device(ip: str) -> tuple[list[str], str, int]:
    """
    Pass A — port scan (-sV):  always runs, failure → WARNING log
    Pass B — OS detection (-O): independent, failure → DEBUG log only
    Returns (open_ports, os_name, os_accuracy).
    """
    import nmap

    open_ports:  list[str] = []
    os_name:     str       = ""
    os_accuracy: int       = 0

    # ── Pass A: Ports ─────────────────────────────────────────────────────────
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments=f"-p {PORT_SCAN_LIST} --open -T4 -sV")

        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port, info in nm[ip][proto].items():
                    if info["state"] == "open":
                        service = info.get("name", "")
                        version = info.get("product", "")
                        label   = f"{port}/{proto}"
                        if service:
                            label += f"({service}"
                            if version:
                                label += f" {version}"
                            label += ")"
                        open_ports.append(label)
            log.info("Ports %s: %s", ip,
                     ", ".join(open_ports) if open_ports else "none open")
        else:
            log.debug("Port scan: %s not in nmap results", ip)

    except Exception as e:
        log.warning("Port scan failed for %s: %s", ip, e)

    # ── Pass B: OS detection ──────────────────────────────────────────────────
    # nmap requires at least one OPEN and one CLOSED port to fingerprint.
    # Without a closed-port RST response it cannot complete TCP sequencing.
    # Port 1 is virtually never open on any device — reliable closed anchor.
    try:
        nm_os = nmap.PortScanner()

        if open_ports:
            # Sanitise: extract only the numeric port before the slash.
            # Guards against a crafted device response injecting into nmap args.
            raw_nums = [p.split("/")[0] for p in open_ports]
            safe_nums = [n for n in raw_nums if n.isdigit() and 1 <= int(n) <= 65535]
            probe_ports = "1," + ",".join(safe_nums) if safe_nums else "1,80,443"
        else:
            probe_ports = "1,22,80,443,8080"  # spread hoping to hit open+closed

        # -T3 (normal) not -T4 (aggressive) — IoT/embedded devices drop probes under fast timing
        os_args = f"-O --osscan-guess -p {probe_ports} -T3"
        nm_os.scan(hosts=ip, arguments=os_args)

        if ip in nm_os.all_hosts():
            hd = nm_os[ip]

            if hd.get("osmatch"):
                best        = hd["osmatch"][0]
                os_name     = best.get("name", "")
                os_accuracy = int(best.get("accuracy", 0))

            if not os_name and hd.get("osclass"):
                cls   = hd["osclass"][0]
                parts = [x for x in [cls.get("vendor", ""),
                                      cls.get("osfamily", ""),
                                      cls.get("osgen", "")] if x]
                os_name     = " ".join(parts)
                os_accuracy = int(cls.get("accuracy", 0))

        if os_name:
            log.info("OS   %s: %s (%d%%)", ip, os_name, os_accuracy)
        else:
            log.debug("OS   %s: undetermined (firewall or too few probe responses)", ip)

    except Exception as e:
        # WARNING level — surfaces permission/capability errors that were previously hidden
        log.warning("OS detection failed for %s: %s", ip, e)

    return open_ports, os_name, os_accuracy


def _scan_and_build(ip: str, host_data, host_ip: str) -> DeviceResult | None:
    """
    Resolve MAC/hostname for one discovered IP, run _scan_device,
    return a DeviceResult or None if MAC can't be resolved.
    Called from thread pool.
    """
    if host_data.state() != "up":
        return None

    # MAC resolution
    mac = ""
    if "addresses" in host_data:
        mac = host_data["addresses"].get("mac", "").upper()
    if not mac:
        mac = _get_mac_from_arp(ip)
    if not mac:
        log.debug("No MAC for %s — skipping", ip)
        return None

    vendor   = get_vendor(mac)
    hostname = ""
    if host_data.get("hostnames"):
        hostname = host_data["hostnames"][0].get("name", "")
    if not hostname:
        hostname = _resolve_hostname(ip)

    open_ports, os_info, os_accuracy = _scan_device(ip)

    # Mark as host if MAC detection earlier failed but IP matches
    is_host = (ip == host_ip and not host_ip == "")

    return DeviceResult(
        mac=mac,
        ip=ip,
        hostname=hostname,
        vendor=vendor,
        open_ports=open_ports,
        os_info=os_info,
        os_accuracy=os_accuracy,
        status="online",
        is_host=is_host,
    )


# ── Main scan entry point ─────────────────────────────────────────────────────

def scan_network() -> list[DeviceResult]:
    """
    Full scan pipeline:
    1.  Self-detect host machine
    2.  ARP ping sweep
    3.  Parallel port+OS scan of all discovered devices
    """
    try:
        import nmap
    except ImportError:
        log.error("python-nmap not installed")
        return []

    results:   list[DeviceResult] = []
    seen_macs: set[str]           = set()

    # ── 1. Host detection ─────────────────────────────────────────────────────
    host_device = get_host_device()
    host_ip     = host_device.ip if host_device else ""

    # ── 2. ARP discovery ──────────────────────────────────────────────────────
    nm_discover = nmap.PortScanner()
    log.info("Host discovery on %s", NETWORK_SUBNET)
    try:
        nm_discover.scan(hosts=NETWORK_SUBNET, arguments="-sn -PR --send-ip")
    except Exception as e:
        log.error("Host discovery failed: %s", e)
        return []

    discovered = nm_discover.all_hosts()
    log.info("Discovered %d hosts", len(discovered))

    # ── 3. Scan host device first ─────────────────────────────────────────────
    if host_device:
        log.info("Scanning host machine %s", host_device.ip)
        host_device.open_ports, host_device.os_info, host_device.os_accuracy = \
            _scan_device(host_device.ip)
        results.append(host_device)
        seen_macs.add(host_device.mac)

    # ── 4. Parallel scan of all other discovered hosts ────────────────────────
    # Filter out host IP first (already handled above)
    to_scan = [(ip, nm_discover[ip]) for ip in discovered if ip != host_ip]

    log.info("Scanning %d device(s) with %d threads", len(to_scan), SCAN_THREADS)

    with ThreadPoolExecutor(max_workers=SCAN_THREADS) as executor:
        futures = {
            executor.submit(_scan_and_build, ip, hd, host_ip): ip
            for ip, hd in to_scan
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                if result is None:
                    continue
                if result.mac in seen_macs:
                    log.debug("Duplicate MAC %s for %s — skipping", result.mac, ip)
                    continue
                seen_macs.add(result.mac)
                results.append(result)
            except Exception as e:
                log.warning("Scan failed for %s: %s", ip, e)

    log.info("Scan complete: %d devices total", len(results))
    return results
