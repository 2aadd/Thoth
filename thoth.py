#!/usr/bin/env python3
"""
thoth.py — Reads all logs under /var/log, finds error patterns,
and generates a colorized summary report.

Named after Thoth, the ancient Egyptian god of knowledge, writing,
and keeper of divine records.

Usage:
  python3 thoth.py                      # scan all of /var/log
  python3 thoth.py -d /var/log/nginx    # specific directory
  python3 thoth.py -f syslog auth.log   # specific files
  python3 thoth.py --html report.html   # generate HTML report
  python3 thoth.py --last 1h            # last 1 hour
  python3 thoth.py --last 24h           # last 24 hours
"""

import os
import re
import sys
import gzip
import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional

# ─── ANSI color codes ────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"

def strip_ansi(text):
    """Strip ANSI escape codes (used for plain-text / HTML output)."""
    return re.sub(r'\033\[[0-9;]*m', '', text)

# ─── Error patterns ──────────────────────────────────────────────────────────
# Each entry: (regex, severity, category, description)

ERROR_PATTERNS = [
    (r'\b(CRITICAL|FATAL|EMERG|ALERT)\b',          'CRITICAL', 'system',   'Critical system error'),
    (r'\b(ERROR|ERR|FAILED|FAILURE)\b',             'ERROR',    'general',  'General error'),
    (r'\bOut of memory\b',                          'CRITICAL', 'memory',   'Out of memory'),
    (r'\bOOM\b|\bkiller\b.*\bpid\b',               'CRITICAL', 'memory',   'OOM killer triggered'),
    (r'\bsegfault|segmentation fault\b',            'CRITICAL', 'crash',    'Segmentation fault'),
    (r'\bkernel panic\b',                           'CRITICAL', 'kernel',   'Kernel panic'),
    (r'\bdisk full|no space left\b',                'CRITICAL', 'disk',     'Disk full'),
    (r'\bI/O error\b',                              'ERROR',    'disk',     'Disk I/O error'),
    (r'\bconnection refused\b',                     'ERROR',    'network',  'Connection refused'),
    (r'\btimed? ?out\b',                            'WARNING',  'network',  'Timeout'),
    (r'\bauthentication failure\b',                 'WARNING',  'auth',     'Authentication failure'),
    (r'\binvalid user\b',                           'WARNING',  'auth',     'Invalid user'),
    (r'\bFailed password\b',                        'WARNING',  'auth',     'Failed password attempt'),
    (r'\bAccepted (password|publickey)\b',          'INFO',     'auth',     'Successful login'),
    (r'\bWARN(?:ING)?\b',                           'WARNING',  'general',  'Warning'),
    (r'\b(refused|reject|deny|blocked)\b',          'WARNING',  'firewall', 'Blocked by firewall'),
    (r'\bssl.*error|certificate.*error\b',          'ERROR',    'ssl',      'SSL/TLS error'),
    (r'\bpermission denied\b',                      'WARNING',  'auth',     'Permission denied'),
    (r'\bcore dumped\b',                            'CRITICAL', 'crash',    'Core dump generated'),
    (r'\bservice.*start\b|\bstarted\b',             'INFO',     'service',  'Service started'),
    (r'\bservice.*stop\b|\bstopped\b',              'INFO',     'service',  'Service stopped'),
    (r'\brestart\b',                                'INFO',     'service',  'Service restarted'),
]

COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), s, c, d)
                     for p, s, c, d in ERROR_PATTERNS]

SEVERITY_ORDER = {'CRITICAL': 0, 'ERROR': 1, 'WARNING': 2, 'INFO': 3}
SEVERITY_COLOR = {
    'CRITICAL': C.BG_RED + C.WHITE + C.BOLD,
    'ERROR':    C.RED + C.BOLD,
    'WARNING':  C.YELLOW,
    'INFO':     C.CYAN,
}

# ─── Data structures ─────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    file:      str
    line_no:   int
    raw:       str
    severity:  str
    category:  str
    desc:      str
    timestamp: Optional[datetime] = None

@dataclass
class FileStats:
    path:         str
    total_lines:  int = 0
    parsed_lines: int = 0
    events:       list = field(default_factory=list)
    errors:       int = 0
    size_bytes:   int = 0

# ─── Timestamp parser ────────────────────────────────────────────────────────

TIMESTAMP_PATTERNS = [
    # syslog:        Jun  4 12:34:56
    (re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'), '%b %d %H:%M:%S'),
    # ISO 8601:      2024-06-04 12:34:56  /  2024-06-04T12:34:56
    (re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'), '%Y-%m-%dT%H:%M:%S'),
    # nginx/apache:  04/Jun/2024:12:34:56
    (re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'), '%d/%b/%Y:%H:%M:%S'),
    # Unix epoch:    1717500000
    (re.compile(r'^(\d{10})\b'), None),
]

def parse_timestamp(line: str) -> Optional[datetime]:
    for pattern, fmt in TIMESTAMP_PATTERNS:
        m = pattern.search(line)
        if m:
            try:
                if fmt is None:
                    return datetime.fromtimestamp(int(m.group(1)))
                ts_str = m.group(1).replace('T', ' ')
                dt = datetime.strptime(ts_str, fmt.replace('T', ' '))
                # syslog timestamps have no year — default to current year
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except (ValueError, OSError):
                pass
    return None

# ─── Log reader ──────────────────────────────────────────────────────────────

def open_log(path: str):
    """Open plain or gzip-compressed log files transparently."""
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', errors='replace', encoding='utf-8')
    return open(path, 'r', errors='replace', encoding='utf-8')

def analyze_file(path: str, since: Optional[datetime] = None) -> FileStats:
    stats = FileStats(path=path)
    try:
        stats.size_bytes = os.path.getsize(path)
    except OSError:
        pass

    try:
        with open_log(path) as f:
            for line_no, raw in enumerate(f, 1):
                stats.total_lines += 1
                raw = raw.rstrip('\n')
                if not raw.strip():
                    continue

                ts = parse_timestamp(raw)

                # skip lines outside the requested time window
                if since and ts and ts < since:
                    continue

                stats.parsed_lines += 1

                # first matching pattern wins
                for pattern, severity, category, desc in COMPILED_PATTERNS:
                    if pattern.search(raw):
                        event = LogEvent(
                            file=path,
                            line_no=line_no,
                            raw=raw[:200],
                            severity=severity,
                            category=category,
                            desc=desc,
                            timestamp=ts,
                        )
                        stats.events.append(event)
                        if severity in ('CRITICAL', 'ERROR'):
                            stats.errors += 1
                        break

    except (PermissionError, OSError) as e:
        print(f"{C.YELLOW}⚠ Skipped: {path} — {e}{C.RESET}")

    return stats

# ─── File discovery ──────────────────────────────────────────────────────────

LOG_EXTENSIONS = {'.log', '.gz', ''}  # also pick up extension-less log files

def discover_logs(directory: str, max_files: int = 50) -> list[str]:
    found = []
    # directories that rarely contain useful plain-text logs
    skip_dirs = {'journal', 'cups', 'dist-upgrade', 'installer', 'unattended-upgrades'}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for fname in sorted(files):
            p = Path(fname)
            if p.suffix in LOG_EXTENSIONS or p.stem.endswith('.log'):
                full = os.path.join(root, fname)
                if os.access(full, os.R_OK):
                    found.append(full)
                if len(found) >= max_files:
                    return found
    return found

# ─── Terminal report ─────────────────────────────────────────────────────────

def fmt_size(b: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

def print_separator(char='─', width=72, color=C.GRAY):
    print(f"{color}{char * width}{C.RESET}")

def print_report(all_stats: list[FileStats], since: Optional[datetime] = None):
    now = datetime.now()

    total_lines  = sum(s.total_lines  for s in all_stats)
    total_events = sum(len(s.events)  for s in all_stats)
    total_errors = sum(s.errors       for s in all_stats)
    total_size   = sum(s.size_bytes   for s in all_stats)

    all_events  = [e for s in all_stats for e in s.events]
    by_severity = Counter(e.severity  for e in all_events)
    by_category = Counter(e.category  for e in all_events)

    # ── Header
    print()
    print_separator('═', color=C.CYAN)
    print(f"{C.CYAN}{C.BOLD}  𓅤  THOTH — LOG ANALYSIS REPORT{C.RESET}")
    print(f"{C.GRAY}  {now.strftime('%Y-%m-%d %H:%M:%S')}"
          + (f"  |  Since: {since.strftime('%Y-%m-%d %H:%M')}" if since else "")
          + C.RESET)
    print_separator('═', color=C.CYAN)

    # ── Summary
    print(f"\n{C.BOLD}  SUMMARY{C.RESET}")
    print_separator()
    for label, val in [
        ("Files analyzed",  f"{len(all_stats)}"),
        ("Total lines",     f"{total_lines:,}"),
        ("Total size",      fmt_size(total_size)),
        ("Events detected", f"{total_events:,}"),
    ]:
        print(f"  {C.GRAY}{label:<28}{C.RESET}{C.WHITE}{val}{C.RESET}")

    # ── Severity breakdown
    print(f"\n{C.BOLD}  SEVERITY BREAKDOWN{C.RESET}")
    print_separator()
    for sev in ['CRITICAL', 'ERROR', 'WARNING', 'INFO']:
        count = by_severity.get(sev, 0)
        color = SEVERITY_COLOR.get(sev, C.RESET)
        bar   = '█' * min(count, 40)
        print(f"  {color}{sev:<10}{C.RESET}  {bar:<40}  {C.WHITE}{count}{C.RESET}")

    # ── Category breakdown
    if by_category:
        print(f"\n{C.BOLD}  CATEGORY BREAKDOWN{C.RESET}")
        print_separator()
        for cat, count in by_category.most_common(10):
            bar = '▪' * min(count, 40)
            print(f"  {C.MAGENTA}{cat:<12}{C.RESET}  {bar:<40}  {count}")

    # ── Per-file summary (sorted by error count, top 15)
    print(f"\n{C.BOLD}  PER-FILE SUMMARY{C.RESET}")
    print_separator()
    files_with_events = sorted(
        [s for s in all_stats if s.events],
        key=lambda s: s.errors,
        reverse=True
    )
    for s in files_with_events[:15]:
        fname   = os.path.basename(s.path)
        c_count = sum(1 for e in s.events if e.severity == 'CRITICAL')
        e_count = sum(1 for e in s.events if e.severity == 'ERROR')
        w_count = sum(1 for e in s.events if e.severity == 'WARNING')
        dot_color = C.RED if c_count else (C.YELLOW if e_count else C.GRAY)
        print(f"  {dot_color}●{C.RESET}  {C.WHITE}{fname:<30}{C.RESET}  "
              f"{C.BG_RED if c_count else C.GRAY} C:{c_count} {C.RESET}  "
              f"{C.RED}E:{e_count}{C.RESET}  "
              f"{C.YELLOW}W:{w_count}{C.RESET}")

    # ── Top critical / error events
    critical_events = sorted(
        [e for e in all_events if e.severity in ('CRITICAL', 'ERROR')],
        key=lambda e: SEVERITY_ORDER.get(e.severity, 99)
    )
    if critical_events:
        print(f"\n{C.BOLD}  CRITICAL / ERROR EVENTS (top 20){C.RESET}")
        print_separator()
        for e in critical_events[:20]:
            color  = SEVERITY_COLOR.get(e.severity, C.RESET)
            fname  = os.path.basename(e.file)
            ts_str = e.timestamp.strftime('%m-%d %H:%M') if e.timestamp else '??-?? ??:??'
            print(f"  {color}[{e.severity[:4]}]{C.RESET}  "
                  f"{C.GRAY}{ts_str}  {fname}:{e.line_no:<5}{C.RESET}")
            print(f"         {C.DIM}{e.raw.strip()[:90]}{C.RESET}")

    # ── Brute-force / attack detection (5+ auth failures triggers this)
    auth_fails = [e for e in all_events
                  if e.category == 'auth' and e.severity == 'WARNING']
    if len(auth_fails) >= 5:
        print(f"\n{C.BOLD}{C.YELLOW}  BRUTE-FORCE / ATTACK DETECTION{C.RESET}")
        print_separator(color=C.YELLOW)
        ip_re     = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
        ip_counts = Counter(ip for e in auth_fails for ip in ip_re.findall(e.raw))
        for ip, cnt in ip_counts.most_common(10):
            bar = '█' * min(cnt, 30)
            print(f"  {C.RED}{ip:<18}{C.RESET}  {bar}  {cnt} attempts")

    # ── Footer verdict
    print()
    print_separator('═', color=C.CYAN)
    if total_errors == 0:
        print(f"{C.GREEN}{C.BOLD}  ✅ System looks clean — no critical errors found.{C.RESET}")
    elif total_errors < 10:
        print(f"{C.YELLOW}{C.BOLD}  ⚠  {total_errors} error(s) found — worth investigating.{C.RESET}")
    else:
        print(f"{C.RED}{C.BOLD}  🚨 {total_errors} errors detected — immediate attention required!{C.RESET}")
    print_separator('═', color=C.CYAN)
    print()

# ─── HTML report ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Thoth — Log Analysis Report</title>
<style>
  :root {{
    --bg:#0d1117;--surface:#161b22;--border:#30363d;
    --text:#c9d1d9;--muted:#8b949e;
    --red:#f85149;--yellow:#e3b341;--green:#3fb950;--blue:#58a6ff;--cyan:#79c0ff;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono','Fira Code',monospace;padding:2rem}}
  h1{{color:var(--cyan);font-size:1.4rem;margin-bottom:.25rem}}
  .sub{{color:var(--muted);font-size:.8rem;margin-bottom:2rem}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem}}
  .card .label{{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.4rem}}
  .card .value{{font-size:1.6rem;font-weight:700}}
  table{{width:100%;border-collapse:collapse;font-size:.8rem;margin-bottom:2rem}}
  th{{color:var(--muted);text-align:left;padding:.5rem .75rem;border-bottom:1px solid var(--border);font-weight:400}}
  td{{padding:.45rem .75rem;border-bottom:1px solid #21262d;vertical-align:top}}
  tr:hover td{{background:#1c2128}}
  .badge{{display:inline-block;padding:1px 8px;border-radius:12px;font-size:.7rem}}
  .badge.CRITICAL{{background:#3d1010;color:var(--red)}}
  .badge.ERROR{{background:#2d1010;color:var(--red);opacity:.8}}
  .badge.WARNING{{background:#2d2010;color:var(--yellow)}}
  .badge.INFO{{background:#102030;color:var(--blue)}}
  .snippet{{color:var(--muted);font-size:.75rem;max-width:500px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
  section{{margin-bottom:2.5rem}}
  h2{{color:var(--cyan);font-size:1rem;margin-bottom:1rem;padding-bottom:.4rem;border-bottom:1px solid var(--border)}}
  .bar-row{{display:flex;align-items:center;gap:.75rem;margin-bottom:.4rem;font-size:.8rem}}
  .bar-label{{width:90px;color:var(--muted)}}
  .bar{{height:14px;border-radius:3px;min-width:4px}}
  .footer{{color:var(--muted);font-size:.75rem;margin-top:2rem;text-align:center}}
</style>
</head>
<body>
<h1>𓅤 Thoth — Log Analysis Report</h1>
<div class="sub">Generated: {generated_at}</div>
<div class="grid">
  <div class="card"><div class="label">Files</div><div class="value" style="color:var(--cyan)">{file_count}</div></div>
  <div class="card"><div class="label">Total Lines</div><div class="value">{total_lines}</div></div>
  <div class="card"><div class="label">Events</div><div class="value" style="color:var(--yellow)">{total_events}</div></div>
  <div class="card"><div class="label">Errors</div><div class="value" style="color:var(--red)">{total_errors}</div></div>
</div>
<section>
  <h2>Severity Distribution</h2>
  {severity_bars}
</section>
<section>
  <h2>Critical / Error Events</h2>
  <table>
    <tr><th>Severity</th><th>Timestamp</th><th>File</th><th>Line</th><th>Content</th></tr>
    {event_rows}
  </table>
</section>
<div class="footer">𓅤 thoth · Keeper of Divine Records · {generated_at}</div>
</body>
</html>"""

def write_html(all_stats: list[FileStats], output_path: str):
    all_events   = [e for s in all_stats for e in s.events]
    by_severity  = Counter(e.severity for e in all_events)
    total_errors = sum(s.errors for s in all_stats)
    total_lines  = sum(s.total_lines for s in all_stats)

    max_sev = max(by_severity.values(), default=1)
    colors  = {'CRITICAL': '#f85149', 'ERROR': '#f85149', 'WARNING': '#e3b341', 'INFO': '#58a6ff'}

    bars = ""
    for sev in ['CRITICAL', 'ERROR', 'WARNING', 'INFO']:
        cnt   = by_severity.get(sev, 0)
        width = max(4, int(cnt / max_sev * 300)) if max_sev else 4
        bars += (f'<div class="bar-row"><span class="bar-label">{sev}</span>'
                 f'<div class="bar" style="width:{width}px;background:{colors[sev]}"></div>'
                 f'<span>{cnt}</span></div>\n')

    critical_events = sorted(
        [e for e in all_events if e.severity in ('CRITICAL', 'ERROR')],
        key=lambda e: SEVERITY_ORDER.get(e.severity, 99)
    )[:50]

    rows = ""
    for e in critical_events:
        ts   = e.timestamp.strftime('%m-%d %H:%M') if e.timestamp else '—'
        snip = e.raw.strip().replace('<', '&lt;').replace('>', '&gt;')[:120]
        rows += (f"<tr><td><span class='badge {e.severity}'>{e.severity}</span></td>"
                 f"<td>{ts}</td><td>{os.path.basename(e.file)}</td><td>{e.line_no}</td>"
                 f"<td class='snippet'>{snip}</td></tr>\n")

    html = HTML_TEMPLATE.format(
        generated_at  = datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        file_count    = len(all_stats),
        total_lines   = f"{total_lines:,}",
        total_events  = f"{len(all_events):,}",
        total_errors  = f"{total_errors:,}",
        severity_bars = bars,
        event_rows    = rows or "<tr><td colspan='5' style='color:#8b949e'>No errors found ✅</td></tr>",
    )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"{C.GREEN}✅ HTML report written: {output_path}{C.RESET}")

# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_since(value: str) -> Optional[datetime]:
    """Parse a human-readable time window (e.g. 6h, 7d, 2w) into a datetime."""
    if not value:
        return None
    m = re.match(r'^(\d+)(h|d|w)$', value.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError("Expected format: 1h, 6h, 24h, 7d, 2w")
    n, unit = int(m.group(1)), m.group(2)
    delta = {'h': timedelta(hours=n), 'd': timedelta(days=n), 'w': timedelta(weeks=n)}[unit]
    return datetime.now() - delta

def main():
    parser = argparse.ArgumentParser(
        description='thoth — Keeper of Divine Records. Finds hidden errors in /var/log and reports them.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('-d', '--dir',      default='/var/log',
                        help='Log directory to scan (default: /var/log)')
    parser.add_argument('-f', '--files',    nargs='+',
                        help='Analyze specific files only')
    parser.add_argument('--last',           metavar='PERIOD',
                        help='Only parse logs from the last N period: 1h, 6h, 24h, 7d, 2w')
    parser.add_argument('--html',           metavar='FILE',
                        help='Write an HTML report to FILE')
    parser.add_argument('--json',           metavar='FILE',
                        help='Write a JSON report to FILE (useful for CI/CD pipelines)')
    parser.add_argument('--max-files',      type=int, default=50,
                        help='Maximum files to scan (default: 50)')
    parser.add_argument('--no-color',       action='store_true',
                        help='Disable color output (useful when piping)')

    args = parser.parse_args()

    # strip all ANSI when --no-color is requested
    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    since = None
    if args.last:
        try:
            since = parse_since(args.last)
        except argparse.ArgumentTypeError as e:
            print(f"{C.RED}Error: {e}{C.RESET}")
            sys.exit(1)

    # build file list
    if args.files:
        log_files = []
        for f in args.files:
            p = f if os.path.isabs(f) else os.path.join(args.dir, f)
            if os.path.isfile(p):
                log_files.append(p)
            else:
                print(f"{C.YELLOW}⚠ Not found: {p}{C.RESET}")
    else:
        print(f"{C.CYAN}🔎 Scanning {args.dir} ...{C.RESET}")
        log_files = discover_logs(args.dir, args.max_files)
        print(f"{C.GRAY}   {len(log_files)} file(s) discovered{C.RESET}")

    if not log_files:
        print(f"{C.RED}No log files found.{C.RESET}")
        sys.exit(1)

    # analyze
    all_stats = []
    for i, path in enumerate(log_files, 1):
        print(f"\r{C.GRAY}  [{i}/{len(log_files)}] {os.path.basename(path)[:40]:<40}{C.RESET}",
              end='', flush=True)
        all_stats.append(analyze_file(path, since))
    print(f"\r{' ' * 60}\r", end='')

    # always print terminal report
    print_report(all_stats, since)

    # optional outputs
    if args.html:
        write_html(all_stats, args.html)

    if args.json:
        all_events = [e for s in all_stats for e in s.events]
        payload = {
            'generated_at':   datetime.now().isoformat(),
            'files_analyzed': len(all_stats),
            'total_events':   len(all_events),
            'events': [
                {
                    'file':      e.file,
                    'line':      e.line_no,
                    'severity':  e.severity,
                    'category':  e.category,
                    'desc':      e.desc,
                    'timestamp': e.timestamp.isoformat() if e.timestamp else None,
                    'raw':       e.raw,
                }
                for e in all_events
            ],
        }
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"{C.GREEN}✅ JSON report written: {args.json}{C.RESET}")

if __name__ == '__main__':
    main()
