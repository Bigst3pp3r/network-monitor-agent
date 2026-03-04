FROM python:3.12-slim

# nmap: scanning + OS detection (-O requires root — we run as root in container)
# net-tools, arp-scan, iputils-ping: ARP cache + host discovery helpers
RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    arp-scan \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor/ ./monitor/
COPY entrypoint.sh ./entrypoint.sh

RUN mkdir -p /app/data /app/logs /app/data/exports && \
    chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
