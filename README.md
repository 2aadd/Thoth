# 𓅤 thoth

> Named after the ancient Egyptian god of knowledge, writing, and keeper of divine records.  
> Reads logs under `/var/log`, finds error patterns, and generates a colorized report.  
> Zero dependencies — Python 3.8+ only.

---

## ⚡ Quick install (curl)

```bash
curl -fsSL https://raw.githubusercontent.com/2aadd/thoth/main/install.sh | bash
```


After install, run from anywhere:

```bash
sudo thoth
```

---

## 📦 Manual install

```bash
git clone https://github.com/2aadd/thoth.git
cd thoth
chmod +x install.sh
./install.sh
```

Or just copy the script:

```bash
sudo cp thoth.py /usr/local/bin/thoth
sudo chmod +x /usr/local/bin/thoth
```

---

## 🚀 Usage

```bash
# Scan all of /var/log
sudo thoth

# Last 6 hours only
sudo thoth --last 6h

# Last 24 hours
sudo thoth --last 24h

# Last 7 days
sudo thoth --last 7d

# Specific directory
sudo thoth -d /var/log/nginx

# Specific files
sudo thoth -f secure auth.log syslog

# Generate HTML report
sudo thoth --html report.html

# JSON output (for CI/CD pipelines)
sudo thoth --json report.json

# Both HTML and JSON, last 24 hours
sudo thoth --last 24h --html report.html --json report.json

# No color (for piping)
sudo thoth --no-color | grep ERROR
```

---

## 🎯 What it detects

| Category | Severity | Examples |
|----------|----------|---------|
| system   | CRITICAL | `FATAL`, `EMERG`, `ALERT` |
| memory   | CRITICAL | OOM killer, `Out of memory` |
| crash    | CRITICAL | `segfault`, `kernel panic`, `core dumped` |
| disk     | CRITICAL | `disk full`, `no space left`, I/O error |
| auth     | WARNING  | Failed password, invalid user, brute-force IP detection |
| network  | ERROR    | Connection refused, timeout |
| ssl      | ERROR    | SSL/TLS errors, certificate errors |
| firewall | WARNING  | `refused`, `blocked`, `deny` |
| service  | INFO     | Service start / stop / restart |

---

## 📊 Sample output

```
════════════════════════════════════════════════════════════════════════
  𓅤  THOTH — LOG ANALYSIS REPORT
  2024-06-04 14:32:11
════════════════════════════════════════════════════════════════════════

  SUMMARY
────────────────────────────────────────────────────────────────────────
  Files analyzed               12
  Total lines                  48,291
  Total size                   18.4 MB
  Events detected              143

  SEVERITY BREAKDOWN
────────────────────────────────────────────────────────────────────────
  CRITICAL    ██                                          2
  ERROR       ████████                                   18
  WARNING     ████████████████████                       89
  INFO        ██████████████████████████████            134

  BRUTE-FORCE / ATTACK DETECTION
────────────────────────────────────────────────────────────────────────
  192.168.1.105       ████████████████  47 attempts
  10.0.0.23           ██████            18 attempts
```

`--html` produces a dark-theme HTML dashboard. Open in any browser, share, or archive.

---

## 🗂 Supported log formats

| Format | Example |
|--------|---------|
| syslog | `Jun  4 12:34:56` |
| ISO 8601 | `2024-06-04T12:34:56` |
| nginx / apache | `04/Jun/2024:12:34:56` |
| Unix epoch | `1717500000` |
| gzip | `.gz` files are read transparently |

---

## 🔧 Requirements

- Python 3.8+
- Linux (Rocky, RHEL, CentOS, Ubuntu, Debian, Arch, …)
- `sudo` to read protected logs like `/var/log/secure`

---

## 💡 Tips

```bash
# Add yourself to the adm group (read logs without sudo on Ubuntu/Debian)
sudo usermod -aG adm $USER

# Daily cron report
echo "0 7 * * * root /usr/local/bin/thoth --last 24h --html /var/www/html/thoth-report.html" \
  | sudo tee /etc/cron.d/thoth

# Email errors to admin
sudo thoth --last 1h --no-color | mail -s "Thoth Report" admin@example.com

# Filter only critical events
sudo thoth --no-color | grep -E "CRITICAL|ERROR"
```

---

## 📁 Repository layout

```
thoth/
├── thoth.py      # main script
├── install.sh    # install script
└── README.md     # this file
```

---

## 📜 License

MIT — do whatever you want with it.
