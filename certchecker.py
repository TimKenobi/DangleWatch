import os
import sys
import requests
import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import argparse
import time
import csv
import glob
import logging
import socket
import subprocess
from jinja2 import Environment, FileSystemLoader
import schedule
import signal

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration - use relative paths for Docker compatibility
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.getenv("OUTPUT_DIR", os.path.join(SCRIPT_DIR, "output"))
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")
LOG_FILE = os.path.join(OUTPUT_DIR, "log.txt")
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "templates")
CHECKPOINT_FILE = os.path.join(OUTPUT_DIR, "weekly_scan_checkpoint.json")
HEALTH_FILE = os.path.join(OUTPUT_DIR, "scan_health.json")
INVESTIGATION_TRACKER_FILE = os.path.join(OUTPUT_DIR, "investigation_tracker.json")

# Scan lock to prevent concurrent scans
SCAN_LOCK = False
CURRENT_SCAN_TYPE = None

# Failure alert thresholds
DAILY_FAILURE_THRESHOLD_DAYS = 3    # Alert if daily scans fail for 3+ days
WEEKLY_FAILURE_THRESHOLD_DAYS = 14  # Alert if weekly scans fail for 2+ weeks
ALERT_COOLDOWN_HOURS = 24           # Don't spam alerts - wait 24h between failure alerts

# Rapid7 InsightIDR Configuration
RAPID7_API_KEY = os.getenv("RAPID7_API_KEY", "")
RAPID7_REGION = os.getenv("RAPID7_REGION", "us3")
RAPID7_API_URL = f"https://{RAPID7_REGION}.api.insight.rapid7.com/idr/v2"
RAPID7_API_URL_V1 = f"https://{RAPID7_REGION}.api.insight.rapid7.com/idr/v1"  # For Comments API

# Cloud provider patterns that are vulnerable to subdomain takeover
VULNERABLE_CNAME_PATTERNS = {
    'azurewebsites.net': 'Azure App Service',
    'cloudapp.azure.com': 'Azure Cloud App',
    'azure-api.net': 'Azure API Management',
    'azurefd.net': 'Azure Front Door',
    'blob.core.windows.net': 'Azure Blob Storage',
    'cloudapp.net': 'Azure Cloud Service',
    'azureedge.net': 'Azure CDN',
    'trafficmanager.net': 'Azure Traffic Manager',
    's3.amazonaws.com': 'AWS S3',
    's3-website': 'AWS S3 Website',
    'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
    'cloudfront.net': 'AWS CloudFront',
    'elb.amazonaws.com': 'AWS ELB',
    'alb.amazonaws.com': 'AWS ALB',
    'execute-api': 'AWS API Gateway',
    'amazonaws.com': 'AWS',
    'herokuapp.com': 'Heroku',
    'herokudns.com': 'Heroku',
    'github.io': 'GitHub Pages',
    'gitbook.io': 'GitBook',
    'ghost.io': 'Ghost',
    'pantheonsite.io': 'Pantheon',
    'zendesk.com': 'Zendesk',
    'shopify.com': 'Shopify',
    'fastly.net': 'Fastly',
    'helpjuice.com': 'Helpjuice',
    'helpscoutdocs.com': 'HelpScout',
    'cargo.site': 'Cargo',
    'statuspage.io': 'Statuspage',
    'tumblr.com': 'Tumblr',
    'wpengine.com': 'WP Engine',
    'desk.com': 'Desk.com',
    'readme.io': 'ReadMe',
    'bitbucket.io': 'Bitbucket',
    'netlify.app': 'Netlify',
    'netlify.com': 'Netlify',
    'vercel.app': 'Vercel',
    'now.sh': 'Vercel',
    'surge.sh': 'Surge',
    'unbouncepages.com': 'Unbounce',
    'cargocollective.com': 'Cargo Collective',
    'fly.dev': 'Fly.io',
    'render.com': 'Render',
    'onrender.com': 'Render',
    'pages.dev': 'Cloudflare Pages',
    'workers.dev': 'Cloudflare Workers',
}

# ============= RAPID7 INSIGHTIDR INTEGRATION =============

def load_investigation_tracker():
    """Load the investigation tracker to prevent duplicates"""
    if not os.path.exists(INVESTIGATION_TRACKER_FILE):
        return {'investigations': {}, 'last_cleanup': None}
    try:
        with open(INVESTIGATION_TRACKER_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load investigation tracker: {e}")
        return {'investigations': {}, 'last_cleanup': None}

def save_investigation_tracker(tracker):
    """Save the investigation tracker"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    try:
        with open(INVESTIGATION_TRACKER_FILE, 'w') as f:
            json.dump(tracker, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save investigation tracker: {e}")

def is_investigation_tracked(subdomain):
    """Check if we already have an open investigation for this subdomain"""
    tracker = load_investigation_tracker()
    inv_info = tracker.get('investigations', {}).get(subdomain)
    
    if not inv_info:
        return False, None
    
    # Check if the investigation is still considered active (within 30 days)
    created_at = inv_info.get('created_at')
    if created_at:
        try:
            created_dt = datetime.fromisoformat(created_at)
            age_days = (datetime.now(ZoneInfo("UTC")) - created_dt).days
            if age_days > 30:
                # Investigation is old, allow creating a new one
                logger.info(f"Investigation for {subdomain} is {age_days} days old, allowing new investigation")
                return False, None
        except:
            pass
    
    return True, inv_info.get('investigation_id')

def track_investigation(subdomain, investigation_id, vulnerability):
    """Track a new investigation to prevent duplicates"""
    tracker = load_investigation_tracker()
    
    if 'investigations' not in tracker:
        tracker['investigations'] = {}
    
    tracker['investigations'][subdomain] = {
        'investigation_id': investigation_id,
        'created_at': datetime.now(ZoneInfo("UTC")).isoformat(),
        'cname_target': vulnerability.get('cname_target'),
        'provider': vulnerability.get('provider'),
        'status': vulnerability.get('status')
    }
    
    save_investigation_tracker(tracker)
    logger.info(f"Tracked investigation {investigation_id} for {subdomain}")

def cleanup_old_investigations():
    """Remove investigations older than 60 days from tracker"""
    tracker = load_investigation_tracker()
    
    # Only cleanup once per day
    last_cleanup = tracker.get('last_cleanup')
    if last_cleanup:
        try:
            last_cleanup_dt = datetime.fromisoformat(last_cleanup)
            hours_since = (datetime.now(ZoneInfo("UTC")) - last_cleanup_dt).total_seconds() / 3600
            if hours_since < 24:
                return
        except:
            pass
    
    cleaned = 0
    investigations = tracker.get('investigations', {})
    to_remove = []
    
    for subdomain, inv_info in investigations.items():
        created_at = inv_info.get('created_at')
        if created_at:
            try:
                created_dt = datetime.fromisoformat(created_at)
                age_days = (datetime.now(ZoneInfo("UTC")) - created_dt).days
                if age_days > 60:
                    to_remove.append(subdomain)
                    cleaned += 1
            except:
                pass
    
    for subdomain in to_remove:
        del tracker['investigations'][subdomain]
    
    tracker['last_cleanup'] = datetime.now(ZoneInfo("UTC")).isoformat()
    save_investigation_tracker(tracker)
    
    if cleaned > 0:
        logger.info(f"Cleaned up {cleaned} old investigations from tracker")

def create_investigation_if_needed(vulnerability):
    """
    Create a Rapid7 investigation for a vulnerability if one doesn't already exist.
    Returns (investigation_id, is_new) tuple.
    """
    subdomain = vulnerability.get('subdomain', 'Unknown')
    
    # Check if we already have an active investigation
    is_tracked, existing_id = is_investigation_tracked(subdomain)
    if is_tracked:
        logger.info(f"Skipping duplicate investigation for {subdomain} - already tracked as {existing_id}")
        return existing_id, False
    
    # Create new investigation
    investigation_id = create_rapid7_investigation(vulnerability)
    
    if investigation_id:
        # Track it to prevent duplicates
        track_investigation(subdomain, investigation_id, vulnerability)
        return investigation_id, True
    
    return None, False

def create_rapid7_investigation(vulnerability):
    """
    Create an investigation in Rapid7 InsightIDR for a subdomain takeover vulnerability.
    Returns investigation ID if successful, None otherwise.
    """
    if not RAPID7_API_KEY:
        return None
    
    subdomain = vulnerability.get('subdomain', 'Unknown')
    cname_target = vulnerability.get('cname_target', 'Unknown')
    provider = vulnerability.get('provider', 'Unknown')
    status = vulnerability.get('status', 'Unknown')
    
    # Always use HIGH priority - CRITICAL can cause alarm
    priority = 'HIGH'
    
    # Create a clean title - details will go in comment
    title = f"[Subdomain Takeover] {subdomain}"
    
    # Create investigation payload (v2 API spec)
    investigation_payload = {
        "title": title[:256],  # API may have title length limit
        "priority": priority,
        "status": "OPEN"
    }
    
    headers = {
        "X-Api-Key": RAPID7_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    try:
        response = requests.post(
            f"{RAPID7_API_URL}/investigations",
            headers=headers,
            json=investigation_payload,
            timeout=30
        )
        response.raise_for_status()
        
        investigation = response.json()
        investigation_rrn = investigation.get('rrn')
        investigation_id = investigation.get('id', 'Unknown')
        
        logger.info(f"Created Rapid7 investigation ({priority}) for {subdomain}: {investigation_id}")
        
        # Add detailed comment to the investigation using v1 API
        if investigation_rrn:
            add_investigation_comment(investigation_rrn, vulnerability, priority)
        
        return investigation_rrn or investigation_id
        
    except requests.exceptions.HTTPError as e:
        logger.error(f"Failed to create Rapid7 investigation for {subdomain}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response: {e.response.text}")
        return None
    except Exception as e:
        logger.error(f"Error creating Rapid7 investigation for {subdomain}: {e}")
        return None

def add_investigation_comment(investigation_rrn, vulnerability, priority):
    """
    Add a detailed comment to a Rapid7 investigation using the v1 Comments API.
    The comment contains all vulnerability details for the analyst.
    """
    if not RAPID7_API_KEY or not investigation_rrn:
        return False
    
    subdomain = vulnerability.get('subdomain', 'Unknown')
    cname_target = vulnerability.get('cname_target', 'Unknown')
    provider = vulnerability.get('provider', 'Unknown')
    status = vulnerability.get('status', 'Unknown')
    
    # Build detailed comment body
    comment_body = f"""## Subdomain Takeover Vulnerability Detected

**Affected Subdomain:** {subdomain}
**CNAME Target:** {cname_target}
**Cloud Provider:** {provider}
**Severity:** {priority}
**Status:** {status}
**Detection Time:** {datetime.now(ZoneInfo("UTC")).strftime('%Y-%m-%d %H:%M:%S UTC')}

---

### Description
A dangling DNS record (CNAME) was detected pointing to a cloud provider resource that no longer exists or is not properly configured. This condition allows an attacker to claim the target resource and serve malicious content under your subdomain.

### Impact
- **Credential Theft:** Phishing pages can be hosted on your trusted domain
- **Malware Distribution:** Malicious files served from your domain bypass user trust barriers
- **Cookie Theft:** Session cookies scoped to the parent domain can be stolen
- **Brand Reputation:** Domain abuse damages customer trust

### Remediation Steps
1. **Verify:** Confirm the subdomain is no longer in use
2. **Remove DNS Record:** Delete the CNAME record from your DNS provider
3. **Or Reclaim:** If the subdomain is still needed, reclaim the cloud resource at {provider}
4. **Verify Fix:** Re-run the certificate checker to confirm remediation

### References
- OWASP: Subdomain Takeover
- https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers

---
*This investigation was automatically created by the Certificate Checker security scanner.*
"""
    
    headers = {
        "X-Api-Key": RAPID7_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    comment_payload = {
        "target": investigation_rrn,
        "body": comment_body
    }
    
    try:
        response = requests.post(
            f"{RAPID7_API_URL_V1}/comments",
            headers=headers,
            json=comment_payload,
            timeout=30
        )
        response.raise_for_status()
        
        logger.info(f"Added detailed comment to investigation for {subdomain}")
        return True
        
    except requests.exceptions.HTTPError as e:
        logger.warning(f"Failed to add comment to investigation for {subdomain}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.warning(f"Response: {e.response.text}")
        return False
    except Exception as e:
        logger.warning(f"Error adding comment to investigation for {subdomain}: {e}")
        return False

def create_investigations_for_vulnerabilities(vulnerabilities):
    """
    Create Rapid7 investigations for vulnerabilities that don't already have one.
    This is a fallback for any vulnerabilities that weren't processed immediately.
    """
    if not RAPID7_API_KEY:
        logger.info("Rapid7 API key not configured - skipping investigation creation")
        return []
    
    if not vulnerabilities:
        return []
    
    # Cleanup old investigations from tracker periodically
    cleanup_old_investigations()
    
    created_investigations = []
    skipped = 0
    
    for vuln in vulnerabilities:
        # Only create investigations for CRITICAL and HIGH severity
        if 'CRITICAL' in vuln.get('status', '') or 'HIGH' in vuln.get('status', ''):
            inv_id, is_new = create_investigation_if_needed(vuln)
            if inv_id:
                created_investigations.append({
                    'subdomain': vuln.get('subdomain'),
                    'investigation_id': inv_id,
                    'is_new': is_new
                })
                if not is_new:
                    skipped += 1
            # Rate limit API calls
            time.sleep(1)
    
    new_count = len([i for i in created_investigations if i.get('is_new', True)])
    if new_count > 0:
        logger.info(f"Created {new_count} new Rapid7 investigations")
    if skipped > 0:
        logger.info(f"Skipped {skipped} duplicate investigations (already being tracked)")
    
    return created_investigations

# ============= CHECKPOINT FUNCTIONS =============

def load_checkpoint():
    """Load checkpoint data for resuming incomplete weekly scans"""
    if not os.path.exists(CHECKPOINT_FILE):
        return None
    try:
        with open(CHECKPOINT_FILE, 'r') as f:
            checkpoint = json.load(f)
        logger.info(f"Loaded checkpoint: {checkpoint.get('completed_count', 0)}/{checkpoint.get('total_domains', 0)} domains completed")
        return checkpoint
    except Exception as e:
        logger.error(f"Failed to load checkpoint: {e}")
        return None

def save_checkpoint(scan_type, domains, completed_domains, all_domain_data, all_takeover_vulns, start_time):
    """Save checkpoint after each domain for resume capability"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    checkpoint = {
        'scan_type': scan_type,
        'domains': domains,
        'completed_domains': completed_domains,
        'completed_count': len(completed_domains),
        'total_domains': len(domains),
        'all_domain_data': all_domain_data,
        'all_takeover_vulns': all_takeover_vulns,
        'start_time': start_time,
        'last_update': datetime.now(ZoneInfo("UTC")).isoformat()
    }
    
    try:
        with open(CHECKPOINT_FILE, 'w') as f:
            json.dump(checkpoint, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save checkpoint: {e}")

def clear_checkpoint():
    """Clear checkpoint after successful completion"""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            os.remove(CHECKPOINT_FILE)
            logger.info("Cleared weekly scan checkpoint")
        except Exception as e:
            logger.error(f"Failed to clear checkpoint: {e}")

def get_checkpoint_age_hours():
    """Get how old the checkpoint is in hours"""
    if not os.path.exists(CHECKPOINT_FILE):
        return None
    try:
        with open(CHECKPOINT_FILE, 'r') as f:
            checkpoint = json.load(f)
        last_update = datetime.fromisoformat(checkpoint.get('last_update', ''))
        age = datetime.now(ZoneInfo("UTC")) - last_update
        return age.total_seconds() / 3600
    except:
        return None

# ============= HEALTH MONITORING FUNCTIONS =============

def load_health_status():
    """Load the current health status from file"""
    if not os.path.exists(HEALTH_FILE):
        return {
            'daily': {'last_success': None, 'consecutive_failures': 0, 'last_alert_sent': None},
            'weekly': {'last_success': None, 'consecutive_failures': 0, 'last_alert_sent': None}
        }
    try:
        with open(HEALTH_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load health status: {e}")
        return {
            'daily': {'last_success': None, 'consecutive_failures': 0, 'last_alert_sent': None},
            'weekly': {'last_success': None, 'consecutive_failures': 0, 'last_alert_sent': None}
        }

def save_health_status(health):
    """Save the current health status to file"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    try:
        with open(HEALTH_FILE, 'w') as f:
            json.dump(health, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save health status: {e}")

def record_scan_success(scan_type):
    """Record a successful scan and reset failure counters"""
    health = load_health_status()
    scan_key = scan_type.lower()
    health[scan_key] = {
        'last_success': datetime.now(ZoneInfo("UTC")).isoformat(),
        'consecutive_failures': 0,
        'last_alert_sent': health.get(scan_key, {}).get('last_alert_sent')
    }
    save_health_status(health)
    logger.info(f"Recorded successful {scan_type} scan")

def record_scan_failure(scan_type, error_message="Unknown error"):
    """Record a scan failure and check if alert should be sent"""
    health = load_health_status()
    scan_key = scan_type.lower()
    
    if scan_key not in health:
        health[scan_key] = {'last_success': None, 'consecutive_failures': 0, 'last_alert_sent': None}
    
    health[scan_key]['consecutive_failures'] = health[scan_key].get('consecutive_failures', 0) + 1
    health[scan_key]['last_failure'] = datetime.now(ZoneInfo("UTC")).isoformat()
    health[scan_key]['last_error'] = error_message
    save_health_status(health)
    
    logger.warning(f"Recorded {scan_type} scan failure #{health[scan_key]['consecutive_failures']}: {error_message}")
    
    # Check if we should send an alert
    check_and_send_health_alert(scan_type, health)

def check_and_send_health_alert(scan_type, health=None):
    """Check if failure threshold exceeded and send alert if needed"""
    if health is None:
        health = load_health_status()
    
    scan_key = scan_type.lower()
    scan_health = health.get(scan_key, {})
    
    # Determine threshold based on scan type
    if scan_key == 'daily':
        threshold_days = DAILY_FAILURE_THRESHOLD_DAYS
    else:
        threshold_days = WEEKLY_FAILURE_THRESHOLD_DAYS
    
    # Check if last success is too old
    last_success = scan_health.get('last_success')
    if last_success:
        try:
            last_success_dt = datetime.fromisoformat(last_success)
            days_since_success = (datetime.now(ZoneInfo("UTC")) - last_success_dt).days
        except:
            days_since_success = threshold_days + 1  # Force alert if can't parse
    else:
        # Never had a successful scan - check consecutive failures
        consecutive_failures = scan_health.get('consecutive_failures', 0)
        if scan_key == 'daily':
            days_since_success = consecutive_failures  # Assume 1 failure = 1 day
        else:
            days_since_success = consecutive_failures * 7  # Weekly = 7 days per failure
    
    # Check if we should send alert
    if days_since_success >= threshold_days:
        # Check cooldown - don't spam alerts
        last_alert = scan_health.get('last_alert_sent')
        if last_alert:
            try:
                last_alert_dt = datetime.fromisoformat(last_alert)
                hours_since_alert = (datetime.now(ZoneInfo("UTC")) - last_alert_dt).total_seconds() / 3600
                if hours_since_alert < ALERT_COOLDOWN_HOURS:
                    logger.debug(f"Skipping health alert - cooldown active ({hours_since_alert:.1f}h < {ALERT_COOLDOWN_HOURS}h)")
                    return
            except:
                pass
        
        # Send the alert
        send_health_alert(scan_type, days_since_success, scan_health)
        
        # Update last alert time
        health[scan_key]['last_alert_sent'] = datetime.now(ZoneInfo("UTC")).isoformat()
        save_health_status(health)

def send_health_alert(scan_type, days_since_success, scan_health):
    """Send a Teams notification about scan failures"""
    if not TEAMS_WEBHOOK_URL:
        logger.warning("Cannot send health alert - no Teams webhook configured")
        return
    
    timestamp = datetime.now(ZoneInfo("UTC")).strftime("%Y-%m-%d %H:%M:%S UTC")
    consecutive_failures = scan_health.get('consecutive_failures', 0)
    last_error = scan_health.get('last_error', 'Unknown')
    last_success = scan_health.get('last_success', 'Never')
    
    # Create alert card
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "text": "⚠️ Certificate Checker Health Alert",
                "weight": "Bolder",
                "size": "Large",
                "color": "Attention"
            },
            {
                "type": "TextBlock",
                "text": f"{scan_type} scans have been failing for {days_since_success} days",
                "wrap": True,
                "color": "Attention"
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Scan Type", "value": scan_type},
                    {"title": "Days Since Success", "value": str(days_since_success)},
                    {"title": "Consecutive Failures", "value": str(consecutive_failures)},
                    {"title": "Last Success", "value": last_success if last_success else "Never"},
                    {"title": "Last Error", "value": last_error[:100] if last_error else "Unknown"},
                    {"title": "Alert Time", "value": timestamp}
                ]
            },
            {
                "type": "TextBlock",
                "text": "Please investigate the certificate checker service.",
                "wrap": True,
                "weight": "Bolder"
            }
        ]
    }
    
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card
            }
        ]
    }
    
    try:
        response = requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=15)
        response.raise_for_status()
        logger.warning(f"Sent health alert for {scan_type} scans - {days_since_success} days without success")
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{time.ctime()}] HEALTH ALERT: {scan_type} scans failing for {days_since_success} days\n")
    except Exception as e:
        logger.error(f"Failed to send health alert: {e}")

def get_health_summary():
    """Get a summary of the current health status"""
    health = load_health_status()
    summary = []
    
    for scan_type in ['daily', 'weekly']:
        scan_health = health.get(scan_type, {})
        last_success = scan_health.get('last_success', 'Never')
        failures = scan_health.get('consecutive_failures', 0)
        
        if last_success and last_success != 'Never':
            try:
                last_success_dt = datetime.fromisoformat(last_success)
                age = datetime.now(ZoneInfo("UTC")) - last_success_dt
                age_str = f"{age.days}d {age.seconds // 3600}h ago"
            except:
                age_str = last_success
        else:
            age_str = "Never"
        
        status = "✅ Healthy" if failures == 0 else f"⚠️ {failures} failures"
        summary.append(f"{scan_type.title()}: {status} (last success: {age_str})")
    
    return summary

# ============= DNS FUNCTIONS =============

def get_cname_record(subdomain):
    """Get CNAME record for a subdomain using dig command"""
    try:
        result = subprocess.run(
            ['dig', '+short', 'CNAME', subdomain],
            capture_output=True,
            text=True,
            timeout=10
        )
        cname = result.stdout.strip().rstrip('.')
        return cname if cname else None
    except Exception as e:
        logger.debug(f"Failed to get CNAME for {subdomain}: {e}")
        return None

def check_dns_resolves(hostname):
    """Check if a hostname resolves to an IP address"""
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

def is_vulnerable_cname(cname_target):
    """Check if a CNAME target matches a vulnerable cloud provider pattern"""
    if not cname_target:
        return None
    cname_lower = cname_target.lower()
    for pattern, provider in VULNERABLE_CNAME_PATTERNS.items():
        if pattern in cname_lower:
            return provider
    return None

def check_subdomain_takeover(subdomain):
    """
    Check if a subdomain is vulnerable to takeover.
    Returns dict with vulnerability info or None if not vulnerable.
    """
    cname = get_cname_record(subdomain)
    if not cname:
        return None
    
    provider = is_vulnerable_cname(cname)
    cname_resolves = check_dns_resolves(cname)
    
    if not cname_resolves:
        if provider:
            return {
                'subdomain': subdomain,
                'cname_target': cname,
                'provider': provider,
                'status': 'CRITICAL - Dangling CNAME to cloud provider (takeover possible)'
            }
        else:
            return {
                'subdomain': subdomain,
                'cname_target': cname,
                'provider': 'Unknown',
                'status': 'HIGH - Dangling CNAME (target does not resolve)'
            }
    
    if provider:
        return {
            'subdomain': subdomain,
            'cname_target': cname,
            'provider': provider,
            'status': 'INFO - External cloud CNAME (monitor for changes)'
        }
    
    return None

def get_subdomains_from_crtsh(domain):
    """Get list of known subdomains from certificate transparency logs"""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        certs = json.loads(response.text)
        
        if not isinstance(certs, list):
            return set()
        
        subdomains = set()
        for cert in certs:
            name_value = cert.get('name_value', '')
            for name in name_value.split('\n'):
                name = name.strip().lower()
                if name and name.endswith(domain.lower()) and '*' not in name:
                    subdomains.add(name)
        
        return subdomains
    except Exception as e:
        logger.error(f"Failed to get subdomains from crt.sh for {domain}: {e}")
        return set()

def scan_domain_for_takeover(domain, created_investigations=None):
    """
    Scan a domain for subdomain takeover vulnerabilities.
    Creates Rapid7 investigations immediately when vulnerabilities are found.
    
    Args:
        domain: The domain to scan
        created_investigations: Optional list to append created investigation info to
    
    Returns:
        List of vulnerability dictionaries
    """
    logger.info(f"Checking subdomain takeover vulnerabilities for {domain}")
    vulnerabilities = []
    
    if created_investigations is None:
        created_investigations = []
    
    subdomains = get_subdomains_from_crtsh(domain)
    logger.info(f"Found {len(subdomains)} subdomains for {domain}")
    
    checked = 0
    for subdomain in subdomains:
        if checked >= 100:
            logger.info(f"Reached subdomain check limit for {domain}")
            break
        
        vuln = check_subdomain_takeover(subdomain)
        if vuln and ('CRITICAL' in vuln['status'] or 'HIGH' in vuln['status']):
            vulnerabilities.append(vuln)
            logger.warning(f"VULNERABLE: {subdomain} -> {vuln['cname_target']} ({vuln['provider']})")
            
            # Create Rapid7 investigation immediately (if not duplicate)
            if RAPID7_API_KEY:
                inv_id, is_new = create_investigation_if_needed(vuln)
                if inv_id and is_new:
                    created_investigations.append({
                        'subdomain': subdomain,
                        'investigation_id': inv_id,
                        'is_new': True
                    })
                    # Rate limit API calls
                    time.sleep(1)
                elif inv_id and not is_new:
                    created_investigations.append({
                        'subdomain': subdomain,
                        'investigation_id': inv_id,
                        'is_new': False
                    })
        
        checked += 1
        time.sleep(0.1)
    
    return vulnerabilities

# ============= NOTIFICATION FUNCTIONS =============

def send_teams_notification(timestamp, all_domain_data, total_new_certs, takeover_vulnerabilities=None, scan_type="Daily", investigations_created=None):
    if not os.path.exists(TEMPLATE_DIR):
        try:
            os.makedirs(TEMPLATE_DIR)
        except Exception as e:
            logger.error(f"Failed to create template directory {TEMPLATE_DIR}: {e}")
            return
    
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    try:
        template = env.get_template('teams_cert_template.j2')
        card_content = template.render(
            timestamp=timestamp,
            total_domains=len(all_domain_data),
            total_new_certs=total_new_certs,
            domain_data=all_domain_data,
            takeover_vulnerabilities=takeover_vulnerabilities or [],
            scan_type=scan_type,
            investigations_created=investigations_created or []
        )
    except Exception as e:
        logger.error(f"Failed to render Teams template: {e}")
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{time.ctime()}] Failed to render Teams template: {e}\n")
        return

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": json.loads(card_content)
            }
        ]
    }

    try:
        response = requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=15)
        response.raise_for_status()
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{time.ctime()}] Teams notification sent successfully ({scan_type} scan)\n")
        logger.info(f"Teams notification sent successfully ({scan_type} scan)")
    except Exception as e:
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{time.ctime()}] Failed to send Teams notification: {e}\n")
        logger.error(f"Failed to send Teams notification: {e}")

# ============= CERTIFICATE FUNCTIONS =============

def is_godaddy_cert(issuer):
    """Check if a certificate is from GoDaddy"""
    godaddy_patterns = ['godaddy', 'go daddy', 'starfield']
    issuer_lower = issuer.lower()
    return any(pattern in issuer_lower for pattern in godaddy_patterns)

def check_new_certificates(domain, retries=3, backoff=2):
    cert_file = os.path.join(OUTPUT_DIR, f"{domain}_certs.txt")
    prev_cert_file = os.path.join(OUTPUT_DIR, f"{domain}_certs_prev.txt")
    new_certs = []
    current_certs = set()
    time.sleep(2)
    
    for attempt in range(retries):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            certs = json.loads(response.text)
            
            if not isinstance(certs, list):
                with open(LOG_FILE, 'a') as log:
                    log.write(f"[{time.ctime()}] Invalid crt.sh response for {domain}: {certs}\n")
                logger.error(f"Invalid crt.sh response for {domain}: {certs}")
                return []
            
            cutoff = datetime.now(ZoneInfo("UTC")) - timedelta(hours=24)
            for cert in certs:
                try:
                    issued_date = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                    issued_date = issued_date.replace(tzinfo=ZoneInfo("UTC"))
                    if issued_date >= cutoff:
                        issuer_name = cert['issuer_name']
                        if not is_godaddy_cert(issuer_name):
                            cert_info = {
                                'domain': cert['name_value'],
                                'issuer': issuer_name,
                                'issued': cert['not_before'],
                                'id': cert['id']
                            }
                            new_certs.append(cert_info)
                except (ValueError, KeyError):
                    continue
            
            try:
                with open(cert_file, 'w') as f:
                    for cert in new_certs:
                        f.write(f"Domain: {cert['domain']}, Issuer: {cert['issuer']}, Issued: {cert['issued']}, ID: {cert['id']}\n")
            except Exception as e:
                logger.error(f"Failed to write certificate file {cert_file}: {e}")
                return []
            
            if os.path.exists(cert_file):
                try:
                    with open(cert_file, 'r') as f:
                        current_certs = set(f.read().splitlines())
                except Exception as e:
                    logger.error(f"Failed to read certificate file {cert_file}: {e}")
                    return []
            
            if os.path.exists(prev_cert_file):
                try:
                    with open(prev_cert_file, 'r') as f:
                        prev_certs = set(f.read().splitlines())
                    new_certs = [cert for cert in new_certs if f"Domain: {cert['domain']}, Issuer: {cert['issuer']}, Issued: {cert['issued']}, ID: {cert['id']}" in current_certs - prev_certs]
                except Exception as e:
                    logger.error(f"Failed to read previous certificate file {prev_cert_file}: {e}")
                    return []
            
            try:
                with open(LOG_FILE, 'a') as log:
                    log.write(f"[{time.ctime()}] Found {len(new_certs)} new certificates for {domain}\n")
                logger.info(f"Found {len(new_certs)} new certificates for {domain}")
            except Exception as e:
                logger.error(f"Failed to write to log file {LOG_FILE}: {e}")
            
            if os.path.exists(cert_file):
                try:
                    os.replace(cert_file, prev_cert_file)
                except Exception as e:
                    logger.error(f"Failed to rename {cert_file} to {prev_cert_file}: {e}")
            
            return new_certs
        except requests.RequestException as e:
            logger.error(f"Certificate check failed for {domain} (attempt {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(backoff * (2 ** attempt))
            continue
        except Exception as e:
            logger.error(f"Unexpected error in certificate check for {domain}: {e}")
            return []
    logger.error(f"All retries failed for certificate check for {domain}")
    return []

# ============= REPORT FUNCTIONS =============

def generate_combined_report(all_domain_data, timestamp, takeover_vulnerabilities=None, scan_type="Daily"):
    if not os.path.exists(OUTPUT_DIR):
        try:
            os.makedirs(OUTPUT_DIR)
        except Exception as e:
            logger.error(f"Failed to create output directory {OUTPUT_DIR}: {e}")
            return "", "", 0
    
    report = f"{scan_type} Website Certificate Report - {timestamp}\n"
    report += "=" * 80 + "\n\n"
    total_new_certs = 0
    csv_file = os.path.join(OUTPUT_DIR, f"cert_report_{scan_type.lower()}_{timestamp.replace(' ', '_').replace(':', '-')}.csv")
    
    if takeover_vulnerabilities:
        report += "⚠️  SUBDOMAIN TAKEOVER VULNERABILITIES DETECTED ⚠️\n"
        report += "=" * 80 + "\n\n"
        for vuln in takeover_vulnerabilities:
            report += f"  {vuln.get('status', 'CRITICAL').split(' - ')[0]}: {vuln['subdomain']}\n"
            report += f"    CNAME Target: {vuln['cname_target']}\n"
            report += f"    Provider: {vuln['provider']}\n"
            report += f"    Status: {vuln['status']}\n\n"
        report += "\n"
    
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Domain", "Certificate Domain", "Issuer", "Issued", "ID"])
            for domain_data in all_domain_data:
                domain = domain_data['domain']
                certificates = domain_data['certificates']
                for cert in certificates:
                    writer.writerow([domain, cert['domain'], cert['issuer'], cert['issued'], cert['id']])
    except Exception as e:
        logger.error(f"Failed to write CSV report {csv_file}: {e}")
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{time.ctime()}] Failed to write CSV report {csv_file}: {e}\n")
        return "", "", 0
    
    for domain_data in all_domain_data:
        domain = domain_data['domain']
        certificates = domain_data['certificates']
        max_cert_domain = max([len(cert['domain']) for cert in certificates] + [6]) if certificates else 6
        max_issuer = max([len(cert['issuer']) for cert in certificates] + [6]) if certificates else 6
        max_issued = max([len(cert['issued']) for cert in certificates] + [6]) if certificates else 6
        max_id = max([len(str(cert['id'])) for cert in certificates] + [2]) if certificates else 2
        report += f"Domain: {domain}\n"
        report += "-" * 50 + "\n\n"
        report += "New Certificates (Last 24 Hours):\n"
        cert_header = f"{'Domain':<{max_cert_domain}} {'Issuer':<{max_issuer}} {'Issued':<{max_issued}} {'ID':<{max_id}}\n"
        report += cert_header
        report += "-" * (max_cert_domain + max_issuer + max_issued + max_id + 9) + "\n"
        if certificates:
            for cert in certificates:
                report += f"{cert['domain']:<{max_cert_domain}} {cert['issuer']:<{max_issuer}} {cert['issued']:<{max_issued}} {cert['id']:<{max_id}}\n"
                total_new_certs += 1
        else:
            report += "None\n"
        report += "\n"
    
    report += "Summary:\n"
    report += "-" * 50 + "\n"
    report += f"- Scan type: {scan_type}\n"
    report += f"- Total domains scanned: {len(all_domain_data)}\n"
    report += f"- Total new certificates: {total_new_certs}\n"
    if takeover_vulnerabilities:
        report += f"- Subdomain takeover vulnerabilities: {len(takeover_vulnerabilities)} ⚠️\n"
    report += f"- Report generated: {timestamp}\n"
    
    return report, csv_file, total_new_certs

def cleanup_old_files(domains):
    """Clean up intermediate files but preserve _certs_prev.txt files needed for tracking."""
    if not os.path.exists(OUTPUT_DIR):
        return
    
    for domain in domains:
        cert_file = os.path.join(OUTPUT_DIR, f"{domain}_certs.txt")
        if os.path.exists(cert_file):
            try:
                os.remove(cert_file)
            except Exception as e:
                logger.error(f"Failed to delete {cert_file}: {e}")

def process_domain(domain):
    logger.info(f"Scanning certificates for {domain}")
    if not os.path.exists(OUTPUT_DIR):
        try:
            os.makedirs(OUTPUT_DIR)
        except Exception as e:
            logger.error(f"Failed to create output directory {OUTPUT_DIR}: {e}")
            return None
    
    certificates = check_new_certificates(domain)
    return {
        'domain': domain,
        'certificates': certificates
    }

# ============= SCAN FUNCTIONS =============

def run_scan(domain_file, scan_type="Daily", use_checkpoint=False):
    """Run a scan of all domains with optional checkpoint/resume for weekly scans"""
    global SCAN_LOCK, CURRENT_SCAN_TYPE
    
    # Check if another scan is running
    if SCAN_LOCK:
        logger.warning(f"Cannot start {scan_type} scan - {CURRENT_SCAN_TYPE} scan already in progress")
        return
    
    # Acquire lock
    SCAN_LOCK = True
    CURRENT_SCAN_TYPE = scan_type
    
    try:
        logger.info(f"Starting {scan_type} certificate scan...")
        
        if not os.path.exists(domain_file):
            error_msg = f"Domain file {domain_file} not found"
            logger.error(error_msg)
            record_scan_failure(scan_type, error_msg)
            return
        
        try:
            with open(domain_file, 'r') as file:
                domains = [line.strip() for line in file if line.strip() and not line.startswith('#')]
        except Exception as e:
            error_msg = f"Error reading domain file {domain_file}: {e}"
            logger.error(error_msg)
            record_scan_failure(scan_type, error_msg)
            return
        
        # Initialize or resume from checkpoint
        all_domain_data = []
        all_takeover_vulns = []
        completed_domains = []
        investigations_created = []  # Track investigations as they're created immediately
        start_time = datetime.now(ZoneInfo("UTC")).isoformat()
        
        if use_checkpoint and scan_type == "Weekly":
            checkpoint = load_checkpoint()
            if checkpoint and checkpoint.get('scan_type') == 'Weekly':
                age_hours = get_checkpoint_age_hours()
                if age_hours is not None and age_hours < 48:
                    completed_domains = checkpoint.get('completed_domains', [])
                    all_domain_data = checkpoint.get('all_domain_data', [])
                    all_takeover_vulns = checkpoint.get('all_takeover_vulns', [])
                    start_time = checkpoint.get('start_time', start_time)
                    logger.info(f"Resuming weekly scan from checkpoint: {len(completed_domains)}/{len(domains)} domains already completed")
                else:
                    logger.info(f"Checkpoint too old ({age_hours:.1f} hours), starting fresh")
                    clear_checkpoint()
        
        remaining_domains = [d for d in domains if d not in completed_domains]
        logger.info(f"{scan_type} scan: Processing {len(remaining_domains)} remaining domains (of {len(domains)} total)")
        
        for i, domain in enumerate(remaining_domains):
            logger.info(f"Scanning certificates for {domain} ({len(completed_domains) + i + 1}/{len(domains)})")
            domain_data = process_domain(domain)
            if domain_data:
                all_domain_data.append(domain_data)
            
            # Scan for takeover vulnerabilities and create investigations immediately
            takeover_vulns = scan_domain_for_takeover(domain, investigations_created)
            all_takeover_vulns.extend(takeover_vulns)
            
            completed_domains.append(domain)
            
            if use_checkpoint and scan_type == "Weekly":
                save_checkpoint(scan_type, domains, completed_domains, all_domain_data, all_takeover_vulns, start_time)
        
        # Generate report
        timestamp = datetime.now(ZoneInfo("UTC")).strftime("%Y-%m-%d %H:%M:%S UTC")
        report, csv_file, total_new_certs = generate_combined_report(all_domain_data, timestamp, all_takeover_vulns, scan_type)
        
        if not report or not csv_file:
            error_msg = "Failed to generate report due to errors"
            logger.error(error_msg)
            record_scan_failure(scan_type, error_msg)
            return
        
        txt_file = os.path.join(OUTPUT_DIR, f"cert_report_{scan_type.lower()}_{timestamp.replace(' ', '_').replace(':', '-')}.txt")
        try:
            with open(txt_file, 'w') as file:
                file.write(report)
        except Exception as e:
            logger.error(f"Failed to write text report {txt_file}: {e}")
            with open(LOG_FILE, 'a') as log:
                log.write(f"[{time.ctime()}] Failed to write text report {txt_file}: {e}\n")
            return
        
        cleanup_old_files(domains)
        
        # Process any vulnerabilities that weren't handled immediately (fallback)
        if all_takeover_vulns:
            logger.warning(f"Found {len(all_takeover_vulns)} subdomain takeover vulnerabilities!")
            # This will only create investigations for any that were missed (deduplication handles it)
            additional_investigations = create_investigations_for_vulnerabilities(all_takeover_vulns)
            # Merge any additional investigations (though there shouldn't be any with immediate creation)
            for inv in additional_investigations:
                if inv not in investigations_created:
                    investigations_created.append(inv)
        
        # Summary of investigations
        new_investigations = [i for i in investigations_created if i.get('is_new', True)]
        existing_investigations = [i for i in investigations_created if not i.get('is_new', True)]
        if new_investigations:
            logger.info(f"Created {len(new_investigations)} new Rapid7 investigations")
        if existing_investigations:
            logger.info(f"Found {len(existing_investigations)} existing investigations (not duplicated)")
        
        # Send notification
        if any(data['certificates'] for data in all_domain_data) or all_takeover_vulns:
            if total_new_certs:
                logger.info(f"Found {total_new_certs} new non-GoDaddy certificates.")
            logger.info("Sending Teams notification...")
            send_teams_notification(timestamp, all_domain_data, total_new_certs, all_takeover_vulns, scan_type, investigations_created)
        else:
            logger.info(f"No new non-GoDaddy certificates or vulnerabilities found ({scan_type} scan)")
        
        # Record successful scan
        record_scan_success(scan_type)
        
        # Clear checkpoint after successful completion
        if use_checkpoint and scan_type == "Weekly":
            clear_checkpoint()
            logger.info("Weekly scan completed successfully!")
    
    finally:
        # Always release scan lock
        SCAN_LOCK = False
        CURRENT_SCAN_TYPE = None

def run_daily_scan(domain_file):
    """Wrapper for daily scan (no checkpoint needed - quick scan)"""
    run_scan(domain_file, "Daily", use_checkpoint=False)

def run_weekly_scan(domain_file):
    """Wrapper for weekly scan with checkpoint/resume capability"""
    run_scan(domain_file, "Weekly", use_checkpoint=True)

def check_and_resume_weekly_scan(domain_file):
    """Check for incomplete weekly scan and resume if found"""
    checkpoint = load_checkpoint()
    if checkpoint and checkpoint.get('scan_type') == 'Weekly':
        age_hours = get_checkpoint_age_hours()
        if age_hours is not None and age_hours < 48:
            completed = checkpoint.get('completed_count', 0)
            total = checkpoint.get('total_domains', 0)
            if completed < total:
                logger.info(f"Found incomplete weekly scan ({completed}/{total} domains). Resuming...")
                run_weekly_scan(domain_file)
                return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Certificate checker with daily and weekly scans")
    parser.add_argument('--domain-file', type=str, default="/app/domains.txt", help="Path to full domain list for weekly scans")
    parser.add_argument('--live-domain-file', type=str, default="/app/livedomains.txt", help="Path to live domain list for daily scans")
    parser.add_argument('--daemon', action='store_true', help="Run as daemon with scheduled scans")
    parser.add_argument('--daily-time', type=str, default="09:00", help="Time to run daily scan (HH:MM format, UTC)")
    parser.add_argument('--weekly-day', type=str, default="sunday", help="Day to run weekly scan (monday, tuesday, etc.)")
    parser.add_argument('--weekly-time', type=str, default="06:00", help="Time to run weekly scan (HH:MM format, UTC)")
    parser.add_argument('--skip-initial-daily', action='store_true', help="Skip the initial daily scan on startup")
    parser.add_argument('--scan-type', type=str, choices=['daily', 'weekly'], default=None, help="Force a specific scan type (daily or weekly)")
    args = parser.parse_args()
    
    if args.daemon:
        logger.info(f"Starting certificate checker in daemon mode")
        logger.info(f"  Daily scan: {args.daily_time} UTC using {args.live_domain_file}")
        logger.info(f"  Weekly scan: {args.weekly_day} at {args.weekly_time} UTC using {args.domain_file}")
        if RAPID7_API_KEY:
            logger.info(f"  Rapid7 InsightIDR integration: ENABLED (region: {RAPID7_REGION})")
        else:
            logger.info(f"  Rapid7 InsightIDR integration: DISABLED (no API key)")
        
        # Log health status on startup
        health_summary = get_health_summary()
        for line in health_summary:
            logger.info(f"  Health: {line}")
        
        # Check for incomplete weekly scan and resume first
        resumed = check_and_resume_weekly_scan(args.domain_file)
        
        # Schedule daily scan (live domains)
        schedule.every().day.at(args.daily_time).do(run_daily_scan, args.live_domain_file)
        
        # Schedule weekly scan (full domain list)
        weekly_schedule = getattr(schedule.every(), args.weekly_day.lower())
        weekly_schedule.at(args.weekly_time).do(run_weekly_scan, args.domain_file)
        
        # Run daily scan on startup only if we didn't resume and not skipped
        if not resumed and not args.skip_initial_daily:
            logger.info("Running initial daily scan...")
            run_daily_scan(args.live_domain_file)
        
        # Handle graceful shutdown
        def signal_handler(signum, frame):
            logger.info("Received shutdown signal. Exiting gracefully...")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Keep running
        while True:
            schedule.run_pending()
            time.sleep(60)
    else:
        # Run once - check for explicit scan type first
        if args.scan_type == 'daily':
            run_daily_scan(args.live_domain_file)
        elif args.scan_type == 'weekly':
            run_weekly_scan(args.domain_file)
        elif args.domain_file and 'domains.txt' in args.domain_file and 'live' not in args.domain_file.lower():
            run_weekly_scan(args.domain_file)
        else:
            run_scan(args.live_domain_file, "Daily")

if __name__ == "__main__":
    main()
