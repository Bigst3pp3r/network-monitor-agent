FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    arp-scan \
    iputils-ping \
    gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor/ ./monitor/
COPY entrypoint.sh ./entrypoint.sh

RUN useradd -m -u 1000 scanner && \
    mkdir -p /app/data /app/logs /app/data/exports && \
    chmod +x /app/entrypoint.sh && \
    chown -R scanner:scanner /app/data /app/logs

ENTRYPOINT ["/app/entrypoint.sh"]
