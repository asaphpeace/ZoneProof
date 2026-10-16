FROM python:3.12-slim

# Build deps for lxml, cryptography; runtime curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-prod.txt .
RUN pip install --no-cache-dir -r requirements-prod.txt

# Download Playwright's Chromium binary (needed for PDF report generation)
RUN playwright install chromium --with-deps

COPY . .

RUN chmod +x entrypoint.sh migrate.sh

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
