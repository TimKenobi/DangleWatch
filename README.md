# Certificate Checker - Docker Deployment

Real-time SSL certificate monitoring and subdomain takeover detection with Rapid7 InsightIDR integration.

## Features

### Certificate Monitoring
- **Daily automated scans** at 09:00 UTC (configurable)
- **Weekly deep scans** on Sundays at 02:00 UTC
- **Filters out GoDaddy certificates** - only reports non-GoDaddy certs
- **Teams notifications** when new certificates are found

### Subdomain Takeover Detection
- **48+ cloud provider patterns** including:
  - AWS (S3, CloudFront, Elastic Beanstalk, ELB, API Gateway)
  - Azure (App Service, Blob Storage, CDN, Traffic Manager, Front Door)
  - Platform services (Heroku, GitHub Pages, Netlify, Vercel, Shopify, Zendesk)
  - And many more...
- **Dangling CNAME detection** - identifies CNAMEs pointing to non-existent resources
- **Automatic vulnerability classification** (CRITICAL/HIGH/MEDIUM/LOW)

### Rapid7 InsightIDR Integration
- **Automatic investigation creation** for detected vulnerabilities
- **Detailed comments** with full vulnerability context
- **Priority: HIGH** for all subdomain takeover findings
- **Duplicate prevention** via investigation tracker

## Quick Start

### Build and run the container:
```bash
cd /opt/certificate_checker
sudo docker compose up -d
```

### View logs:
```bash
sudo docker compose logs -f
```

### Stop the container:
```bash
sudo docker compose down
```

### Rebuild after code changes:
```bash
sudo docker compose down
sudo docker compose build --no-cache
sudo docker compose up -d
```

## Configuration

### Change scan time:
Edit `docker-compose.yml` and modify the `--scan-time` parameter (format: HH:MM in UTC):
```yaml
command: ["python", "certchecker.py", "--daemon", "--scan-time", "14:00"]
```

### Update domains:
Edit `domains.txt` and restart the container:
```bash
sudo docker compose restart
```

### Rapid7 API Configuration:
The API key and region are configured in `certchecker.py`:
```python
RAPID7_API_KEY = "your-api-key"
RAPID7_REGION = "us3"  # or us, us2, eu, au, ca
```

### Teams Webhook:
Set the environment variable in `docker-compose.yml`:
```yaml
environment:
  - TEAMS_WEBHOOK_URL=your_webhook_url_here
```

## Manual Scan

Run a manual scan without waiting for schedule:
```bash
# Full scan
sudo docker exec certificate_checker python certchecker.py

# Daily scan only
sudo docker exec certificate_checker python certchecker.py --scan-type daily

# Weekly scan only
sudo docker exec certificate_checker python certchecker.py --scan-type weekly
```

## Output Files

All reports are saved to the `output/` directory:
- `cert_report_*.txt` - Text reports
- `cert_report_*.csv` - CSV reports for Excel
- `*_certs_prev.txt` - Previous scan state for change detection
- `investigation_tracker.json` - Tracks created Rapid7 investigations
- `log.txt` - Application logs

## Scan Lock Mechanism

The scanner prevents concurrent scans:
- Only one scan (daily or weekly) runs at a time
- If a scan is in progress, the other scan type waits
- Ensures no duplicate processing

## How It Works

1. Container starts in daemon mode
2. **Daily scans** (09:00 UTC): Certificate monitoring + subdomain checks
3. **Weekly scans** (Sunday 02:00 UTC): Deep subdomain takeover analysis
4. For each vulnerability found:
   - Creates Rapid7 InsightIDR investigation (Priority: HIGH)
   - Adds detailed comment with CNAME target, provider, and remediation steps
   - Tracks investigation to prevent duplicates
5. GoDaddy certificates are filtered from reports
6. Teams notification sent for new findings

## Vulnerability Severity

| Severity | Description |
|----------|-------------|
| CRITICAL | Dangling CNAME to known cloud provider - immediate takeover risk |
| HIGH | Dangling CNAME to unknown provider |
| MEDIUM | Active cloud service CNAME - monitor for changes |
| LOW | Informational findings |

## Dependencies

- Python 3.11
- dnspython, requests, schedule
- Docker with compose

## Repository

https://gitea.stahlsitsec.local/bransont/certificate_checker
