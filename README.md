# Apache Attack Scanner

This lightweight PHP script monitors recent Apache access logs for signs of automated attacks or suspicious traffic and blocks offending IP addresses in real-time. It’s optimized for speed and can be safely run every few minutes via cron or manually.

---

## 🚀 Features

- ✅ Blazing-fast (runs in < 1 second even with multiple vhosts)
- 🔎 Scans the **tail** of Apache logs (configurable)
- 🧠 Detects known attack patterns (e.g. `wp-login.php`, `xmlrpc.php`, `eval()`)
- 🛡 Blocks abusive IPs with `iptables`
- ❌ Skips Cloudflare and whitelisted IPs
- 📤 Sends alerts to a specified Slack channel via Bot Token
- 📝 Maintains persistent allowlist and blocklist
- 🧩 Easy to customize patterns, thresholds, and log locations

---

## 📂 File Structure

```
apache_attack_scan.php         # Main PHP script
/var/log/apache-blocked-ips.txt # Stores blocked IPs
/etc/apache-attack-whitelist.txt # List of IPs to ignore (one per line)
```

---

## ⚙️ Configuration

Edit the top section of `apache_attack_scan.php`:

```php
$logDir = '/var/log/httpd';               // Directory where your access logs are
$tailLines = 200;                         // Lines to scan from each log
$threshold = 5;                           // Min hits per IP to be considered abusive
$blockEnabled = true;                     // Set to false to disable IP blocking

$blocklistFile = '/var/log/apache-blocked-ips.txt';
$whitelistFile = '/etc/apache-attack-whitelist.txt';

$slackToken = 'xoxb-xxxxxxxxxxxxxxxxxxxxx'; // Your Slack Bot token
$slackChannel = '#alerts';                 // Channel name or ID
```

---

## 🛑 Block & Allow Lists

- **Whitelist:** `/etc/apache-attack-whitelist.txt`
  - Add trusted IPs to prevent blocking (one IP per line)

- **Blocklist:** `/var/log/apache-blocked-ips.txt`
  - Automatically updated when IPs are blocked
  - Prevents re-blocking already blocked IPs

---

## 📤 Slack Alerts

Alerts are sent via the Slack Bot API.

- Requires a bot token with `chat:write` permission.
- Configure `SLACK_TOKEN` and `SLACK_CHANNEL` at the top of the script.

Example alert:

```
:rotating_light: Blocked IP: 192.0.2.10
Domain: example.com
URL: /wp-login.php
Count: 7
```

---

## 🧪 Example Cron Job

Run every 10 minutes:

```bash
*/10 * * * * php /usr/local/bin/block_suspicious_attacks.php
```

---

## ✅ Requirements

- PHP 7.0+
- `iptables` (for blocking)
- Apache log format with IP and request path in each line
- Slack bot token (optional but recommended)

---

## 🛡 Recommended Use

- Monitor servers with multiple virtual hosts
- Block brute-force attacks against WordPress or PHP backdoors
- Deploy on shared hosting environments with mod_log_config per vhost

---

## 🔒 Security Note

- Only use `iptables` if you're confident in your firewall rules.
- Always maintain a whitelist of trusted IPs.

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Created by [Michael Patrick](https://www.dragonsociety.com)  
