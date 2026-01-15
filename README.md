# DangleWatch 🔐

Real-time SSL certificate monitoring and subdomain takeover detection with Microsoft Teams notifications and optional Rapid7 InsightIDR integration.

## Features

### 🔍 Certificate Monitoring
- **Daily automated scans** for new SSL certificates
- **Weekly deep scans** for comprehensive analysis
- **Certificate transparency log monitoring** via crt.sh
- **Configurable certificate issuer filtering** (e.g., exclude GoDaddy certs)
- **Microsoft Teams notifications** for new certificate discoveries

### 🚨 Subdomain Takeover Detection
- **48+ cloud provider patterns** including:
  - AWS (S3, CloudFront, Elastic Beanstalk, ELB, API Gateway)
  - Azure (App Service, Blob Storage, CDN, Traffic Manager, Front Door)
  - Platform services (Heroku, GitHub Pages, Netlify, Vercel, Shopify, Zendesk)
  - Modern platforms (Cloudflare Pages/Workers, Fly.io, Render)
- **Dangling CNAME detection** - identifies CNAMEs pointing to non-existent resources
- **Automatic vulnerability classification** (CRITICAL/HIGH/MEDIUM/LOW)

### 🔗 Rapid7 InsightIDR Integration (Optional)
- **Automatic investigation creation** for detected vulnerabilities
- **Detailed comments** with full vulnerability context and remediation steps
- **Duplicate prevention** via investigation tracking
- **Priority: HIGH** for all subdomain takeover findings

### 📊 Health Monitoring
- **Scan health tracking** - monitors for consecutive failures
- **Automatic alerts** when scans fail for extended periods
- **Checkpoint/resume** for long-running weekly scans

## Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/TimKenobi/DangleWatch.git
cd DangleWatch
```

### 2. Create your configuration
```bash
# Copy the example environment file
cp .env.example .env

# Edit with your settings
nano .env
```

### 3. Add your domains
```bash
# Edit domains.txt with your full domain list (for weekly scans)
nano domains.txt

# Edit livedomains.txt with critical domains (for daily scans)
nano livedomains.txt
```

### 4. Run with Docker
```bash
# Build and start the container
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `TEAMS_WEBHOOK_URL` | Microsoft Teams webhook URL for notifications | No |
| `RAPID7_API_KEY` | Rapid7 InsightIDR API key | No |
| `RAPID7_REGION` | Rapid7 region (us, us2, us3, eu, au, ca) | No (default: us3) |
| `OUTPUT_DIR` | Output directory for reports | No (default: ./output) |
| `TZ` | Timezone | No (default: UTC) |

### Scan Schedule

Modify the schedule in the Dockerfile CMD or via command line:

```bash
# Daily scans at 09:00 UTC
# Weekly scans on Sunday at 06:00 UTC
python certchecker.py --daemon \
  --daily-time "09:00" \
  --weekly-day "sunday" \
  --weekly-time "06:00" \
  --domain-file domains.txt \
  --live-domain-file livedomains.txt
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--domain-file` | Full domain list for weekly scans | `/app/domains.txt` |
| `--live-domain-file` | Critical domains for daily scans | `/app/livedomains.txt` |
| `--daemon` | Run as daemon with scheduled scans | false |
| `--daily-time` | Time for daily scan (HH:MM, UTC) | `09:00` |
| `--weekly-day` | Day for weekly scan | `sunday` |
| `--weekly-time` | Time for weekly scan (HH:MM, UTC) | `06:00` |
| `--scan-type` | Force specific scan type (daily/weekly) | auto |
| `--skip-initial-daily` | Skip daily scan on startup | false |

## Manual Scans

```bash
# Run daily scan
docker exec danglewatch python certchecker.py --scan-type daily

# Run weekly scan
docker exec danglewatch python certchecker.py --scan-type weekly

# Run with default behavior
docker exec danglewatch python certchecker.py
```

## Output Files

Reports are saved to the `output/` directory:
- `cert_report_daily_*.csv` - Daily scan CSV reports
- `cert_report_daily_*.txt` - Daily scan text reports
- `cert_report_weekly_*.csv` - Weekly scan CSV reports
- `cert_report_weekly_*.txt` - Weekly scan text reports
- `*_certs_prev.txt` - Previous scan state for change detection
- `scan_health.json` - Health monitoring status
- `investigation_tracker.json` - Rapid7 investigation tracking (if enabled)
- `log.txt` - Application logs

## Domain File Format

### domains.txt (Full list for weekly scans)
```
example.com
example.org
mycompany.com
```

### livedomains.txt (Critical domains for daily scans)
```
www.example.com
api.example.com
portal.mycompany.com
```

Lines starting with `#` are treated as comments.

### false_positives.txt (Exclude known-safe subdomains)

Use this file to exclude subdomains from subdomain takeover detection that are known false positives:

```
# False Positives - Subdomain Takeover Detection
# Add one subdomain per line to exclude from vulnerability reports
host.REMOVED.com
kiosk.stahls.com
one-stahl-mfg-staging.stahls.com
```

When a subdomain is listed in `false_positives.txt`:
- It will be skipped during subdomain takeover checks
- No Rapid7 investigations will be created for it
- No Teams notifications will be sent for it

This is useful for subdomains that appear vulnerable but are actually:
- Intentionally configured with non-resolving CNAMEs
- In the process of being migrated
- Third-party services with expected behavior

## Microsoft Teams Integration

1. Create an Incoming Webhook in your Teams channel
2. Copy the webhook URL
3. Set `TEAMS_WEBHOOK_URL` in your `.env` file

Notifications include:
- New certificate discoveries (non-GoDaddy)
- Subdomain takeover vulnerabilities
- Investigation creation status (if Rapid7 enabled)

## Rapid7 InsightIDR Integration

1. Generate an API key in InsightIDR Platform Settings
2. Set `RAPID7_API_KEY` in your `.env` file
3. Set `RAPID7_REGION` to match your InsightIDR region

When vulnerabilities are detected:
- Investigations are automatically created in InsightIDR
- Detailed comments explain the vulnerability and remediation steps
- Duplicate investigations are prevented via local tracking

## Security Recommendations

When dangling CNAMEs are detected:

1. **Verify**: Confirm the subdomain is no longer needed
2. **Remove**: Delete the DNS record from your DNS provider
3. **Or Reclaim**: If still needed, reclaim the cloud resource
4. **Monitor**: Re-run DangleWatch to verify the fix

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

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
- requests, jinja2, schedule, python-dateutil
- dnsutils (for dig command)
- Docker with compose

## Repository

https://gitea.stahlsitsec.local/bransont/certificate_checker
