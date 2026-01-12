FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dnsutils for dig command (needed for subdomain takeover detection)
RUN apt-get update && apt-get install -y dnsutils && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY certchecker.py .
COPY domains.txt .
COPY livedomains.txt .
COPY templates/ templates/

# Create output directory
RUN mkdir -p output

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Run the application in daemon mode with daily and weekly schedules
# Daily scans: livedomains.txt (53 domains) at 09:00 UTC
# Weekly scans: domains.txt (586 domains) on Sunday at 06:00 UTC
CMD ["python", "certchecker.py", "--daemon", "--domain-file", "/app/domains.txt", "--live-domain-file", "/app/livedomains.txt", "--daily-time", "09:00", "--weekly-day", "sunday", "--weekly-time", "06:00"]
