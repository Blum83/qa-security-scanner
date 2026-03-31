FROM python:3.11-slim

# Install Nuclei v3.7.1
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.7.1/nuclei_3.7.1_linux_amd64.zip -O nuclei.zip && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei.zip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directory for SQLite persistence
RUN mkdir -p /app/data && chmod 777 /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
