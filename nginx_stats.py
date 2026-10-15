#!/usr/bin/env python3
"""
nginx_stats: most accessed URLs, referrers, hosts, IPs... from nginx logs.

Reads every rotated file (access.log, access.log.1, access.log.2.gz...) in
/var/log/nginx and opens an interactive view in the terminal. Python 3
standard library only, so it runs as is on any server.

    ./nginx_stats.py                       interactive, access.log*
    ./nginx_stats.py blocked               blocked.log*
    ./nginx_stats.py /var/log/nginx /srv/logs/oldserver   both folders together
    ./nginx_stats.py --days 1 --host dmtr.org
    ./nginx_stats.py --text --top 30       plain report (cron, mail, pipes)
    ./nginx_stats.py --dump stats.md       everything, as Markdown for an LLM
    ./nginx_stats.py --unparsed            which lines could not be read, and why
"""

import argparse
import curses
import datetime
import glob
import gzip
import ipaddress
import locale
import os
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

LOG_DIR = os.environ.get('NGINX_LOG_DIR', '/var/log/nginx')
HERE = os.path.dirname(os.path.realpath(__file__))
# where server_name lines tell real sites from host names made up by scanners
NGINX_CONF = ['/etc/nginx', os.path.join(HERE, '..', '_nginx')]

# combined format, then optional extra quoted fields. Ours (log_format main):
# ... "$http_user_agent" "$http_x_forwarded_for" "$host"
# Also read: common format (no referrer/agent), quotes escaped as \" (Apache),
# a host name before the IP (vhost_combined) and $time_iso8601.
Q = r'"([^"\\]*(?:\\.[^"\\]*)*)"'
LINE = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] ' + Q + r' (\d{3}) (\d+|-)(?: ' + Q + ' ' + Q + r')?(.*)')
VHOST = re.compile(r'(\S+) ' + LINE.pattern)
EXTRA = re.compile(Q)
MONTHS = {m: '%02d' % i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}
STATIC = re.compile(r'\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|ogg)$', re.I)
NO_UA = '(not logged)'

# --- who is a bot ---
BOTS = re.compile(
    r'bot|crawl|spider|slurp|scan|curl|wget|python|go-http|java/|libwww|perl|ruby|php/|okhttp|axios|'
    r'node-fetch|httpclient|http-client|headless|lighthouse|facebookexternalhit|preview|feed|monitor|'
    r'uptime|zgrab|masscan|nmap|nikto|sqlmap|ahrefs|semrush|mj12|dataprovider|censys|expanse|palo alto|'
    r'worker|fetch|proxy', re.I)
DECLARED = re.compile(r'https?://|@|\bcompatible;', re.I)      # bots sign with a url or e-mail
BROWSER = re.compile(r'Safari/|Firefox/|Mobile/')              # every real browser has one
VERSION = re.compile(r'(Chrome|Firefox)/(\d+)')
OUTDATED = 18           # versions behind the newest one in the logs (about 1.5 years)
PROBES = re.compile(
    r'/\.(?:env|git|svn|hg|aws|ssh|docker|vscode|idea|DS_Store|htpasswd|htaccess|npmrc|bash_history)|'
    r'wp-(?:login|admin|content|includes|config|json)|xmlrpc\.php|phpinfo|php-info|eval-stdin|'
    r'/vendor/phpunit|/cgi-bin/|/@fs/|__vite|/telescope|_debugbar|/actuator|/HNAP1|/boaform|/geoserver|'
    r'/solr/|containers/json|sftp-config|/phpmyadmin|/pma/|/myadmin|/autodiscover|/owa/|/ecp/|'
    r'/remote/login|/dana-na/|/global-protect|/manager/html', re.I)
REASONS = {
    'bot user agent': 'says it is a bot or tool (bot, crawler, curl, python, a +http contact link...)',
    'not a browser': 'user agent does not start with Mozilla/ (WordPress/, libredtail-http, crusader-worker...)',
    'fake browser agent': 'starts with Mozilla/ but has no browser in it (bare "Mozilla/5.0", Chrome without Safari/...)',
    'outdated browser': f'Chrome or Firefox {OUTDATED}+ versions behind the newest one in these logs',
    'empty user agent': 'no user agent at all',
    'probing IP': 'IP that asked for .env, .git, wp-login, phpinfo... (all its requests count)',
    'error-heavy IP': 'IP with 20+ requests, 80%+ of them 4xx',
    'malformed request': 'request line is not "METHOD /path HTTP/x" (TLS on http, binary junk)',
}

# record fields
IP, DAY, HOUR, METHOD, PATH, STATUS, BYTES, REF, SITE, UA, HOST, ASSET = range(12)

# name, record field, sort by key instead of count
PANELS = [
    ('Overview', None, False),
    ('Days', DAY, True),
    ('URLs', PATH, False),
    ('Data', PATH, False),         # bytes sent per url
    ('Hosts', HOST, False),
    ('Sites', SITE, False),        # external referring sites
    ('Referrers', REF, False),     # external referrers, full url
    ('Status', STATUS, False),
    ('404s', PATH, False),
    ('IPs', IP, False),
    ('Agents', UA, False),
]
BYTE_PANELS = {'Data'}
FIELD_NAMES = {DAY: 'day', PATH: 'url', HOST: 'host', SITE: 'site', REF: 'ref', STATUS: 'status', IP: 'ip', UA: 'agent'}


# --- reading ---------------------------------------------------------------

def is_xff(value):
    if value == '-':
        return True
    try:
        for part in value.split(','):
            ipaddress.ip_address(part.strip())
        return True
    except ValueError:
        return False


def www(host):
    return host[4:] if host.startswith('www.') else host


class Parser:
    def __init__(self):
        self.sites = {}

    def site(self, ref):
        if ref not in self.sites:
            try:    # some clients send a list: "https://google.com, https://..."
                host = urlsplit(ref.split(',')[0].split()[0]).hostname or ''
            except (ValueError, IndexError):
                host = ''
            self.sites[ref] = sys.intern(www(host))
        return self.sites[ref]

    def parse(self, line):
        vhost = ''
        m = LINE.match(line)
        if not m:
            m = VHOST.match(line)
            if not m:
                return None
            vhost = m.group(1)
            ip, t, req, status, size, ref, ua, rest = m.groups()[1:]
        else:
            ip, t, req, status, size, ref, ua, rest = m.groups()

        if t[2:3] == '/':               # 15/Oct/2026:18:34:01 -0300
            month = MONTHS.get(t[3:6])
            if not month:
                return None
            day, hour = f'{t[7:11]}-{month}-{t[0:2]}', t[12:14]
        elif t[4:5] == '-':             # 2026-10-15T18:34:01-03:00
            day, hour = t[:10], t[11:13]
        else:
            return None
        if not hour.isdigit():
            return None

        parts = req.split(' ')
        if len(parts) == 3:
            method, uri = parts[0], parts[1]
        else:
            method, uri = '-', req      # junk sent by scanners
        path = sys.intern(uri.split('?', 1)[0])

        if ref is None and '"' in rest:
            return None                 # referrer or agent cut short
        # "$http_x_forwarded_for" "$host", or just one of them
        extra = EXTRA.findall(rest)
        host = vhost.rsplit(':', 1)[0] if vhost else ''
        if len(extra) >= 2:
            host = extra[-1]
        elif extra and not is_xff(extra[0]):
            host = extra[0]
        host = sys.intern(host.lower())

        if ref is None:
            ref, ua = '-', NO_UA
        site = None
        if ref != '-':
            s = self.site(ref)
            if s and s != www(host):
                site = s
        return (sys.intern(ip), sys.intern(day), int(hour), sys.intern(method), path, int(status),
                0 if size == '-' else int(size), sys.intern(ref), site, sys.intern(ua), host,
                bool(STATIC.search(path)))


# --- lines that could not be read ---

SHAPE_QUOTED = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"')
SHAPE_BRACKET = re.compile(r'\[[^\]]*\]')
SHAPE_IP = re.compile(r'^(\d{1,3}(\.\d{1,3}){3}(:\d+)?|[0-9a-f:]*::[0-9a-f:.]*|([0-9a-f]{1,4}:){5,}[0-9a-f.]+)$', re.I)
EXPECTED = 'IP - - [time] "…" N N "…" "…" "…" "…"'


def shape(line):
    """A line reduced to its layout: IP - - [time] "…" N N "…" ..."""
    s = line.strip()
    if s.startswith('{'):
        return 'JSON {…}'
    s = SHAPE_BRACKET.sub(' \x01T ', SHAPE_QUOTED.sub(' \x01Q ', s))
    out = []
    for tok in s.split()[:14]:
        if tok == '\x01Q':
            out.append('"…"')
        elif tok == '\x01T':
            out.append('[time]')
        elif tok == '-':
            out.append('-')
        elif SHAPE_IP.match(tok):
            out.append('IP')
        elif tok.isdigit():
            out.append('N')
        else:
            out.append('word')
    return ' '.join(out)


def guess(sh, example):
    if sh.startswith('JSON'):
        return 'JSON lines (log_format with escape=json): not supported yet'
    if re.match(r'\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[\w+\]', example):
        return 'nginx error.log line, not an access log'
    if example.count('"') % 2:
        return 'odd number of quotes: a field with a raw " inside, or a cut line'
    if '[time]' not in sh:
        return 'no [time] field: different log_format'
    if not sh.startswith('IP'):
        return 'does not start with the client IP: different log_format'
    if sh.count('"…"') < 1:
        return 'request is not quoted: different log_format'
    if not example.rstrip().endswith('"') and sh.count('"…"') < 3:
        return 'line cut short (disk full, crash or rotation)'
    return 'different log_format: compare with the expected shape'


class Unparsed:
    def __init__(self):
        self.files = {}                 # file -> [parsed, unparsed]
        self.shapes = Counter()
        self.example = {}
        self.where = defaultdict(set)

    def add(self, f, line):
        sh = shape(line)
        if sh not in self.shapes and len(self.shapes) >= 500:
            sh = '(other shapes)'
        self.shapes[sh] += 1
        self.example.setdefault(sh, line.strip()[:400])
        self.where[sh].add(os.path.basename(f))

    @property
    def total(self):
        return sum(bad for _, bad in self.files.values())

    def rows(self, n=10):
        """(lines, guess, shape, files, example), most common first."""
        return [(c, guess(sh, self.example[sh]), sh, ', '.join(sorted(self.where[sh])[:4])
                 + (f' +{len(self.where[sh]) - 4}' if len(self.where[sh]) > 4 else ''), self.example[sh])
                for sh, c in self.shapes.most_common(n)]


def log_files(sources, directory):
    """Files for each source: a name in directory (access, blocked), a folder
    (its access.log*), a file or a glob. Oldest rotation first, no repeats."""
    def rotation(f):
        m = re.search(r'\.(\d+)(\.gz)?$', f)
        return int(m.group(1)) if m else 0

    files, seen = [], set()
    for src in sources:
        if os.path.isdir(src):
            found = glob.glob(os.path.join(src, 'access.log*'))
        elif os.path.isfile(src):
            found = [src]
        elif os.sep in src:
            found = glob.glob(src)
        else:
            found = glob.glob(os.path.join(directory, src + '.log*'))
        if not found:
            print(f'nothing found for {src!r}', file=sys.stderr)
        for f in sorted(found, key=rotation, reverse=True):
            real = os.path.realpath(f)
            if real not in seen and os.path.isfile(f):
                seen.add(real)
                files.append(f)
    return files


def load(files, days=None, progress=None):
    parser, records, bad = Parser(), [], Unparsed()
    oldest = datetime.datetime.now().timestamp() - (days + 1) * 86400 if days else 0
    for f in files:
        good = wrong = 0
        try:
            if os.path.getmtime(f) < oldest:
                continue
            if progress:
                progress(f)
            opener = gzip.open if f.endswith('.gz') else open
            with opener(f, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    r = parser.parse(line)
                    if r:
                        records.append(r)
                        good += 1
                    elif line.strip():
                        bad.add(f, line)
                        wrong += 1
        except (OSError, EOFError) as e:
            print(f'skipping {f}: {e}', file=sys.stderr)
        bad.files[f] = [good, wrong]
    if days and records:
        last = datetime.date.fromisoformat(max(r[DAY] for r in records))
        first = (last - datetime.timedelta(days=days - 1)).isoformat()
        records = [r for r in records if r[DAY] >= first]
    return records, bad


# --- known sites -----------------------------------------------------------

class KnownHosts:
    """Host names from server_name lines in the nginx config."""
    def __init__(self, places):
        self.exact, self.suffix, self.prefix, self.regex = set(), [], [], []
        self.files = []
        for place in places:
            paths = (glob.glob(os.path.join(place, '**', '*.conf'), recursive=True)
                     + glob.glob(os.path.join(place, 'sites-enabled', '*'))) if os.path.isdir(place) else []
            if place.endswith('_nginx'):    # our repo: only the live top level, not _fusk/ etc.
                paths = glob.glob(os.path.join(place, '*.conf'))
            for p in paths:
                try:
                    text = open(p, encoding='utf-8', errors='replace').read()
                except OSError:
                    continue
                names = re.findall(r'^[ \t]*server_name\s+([^;]+);', text, re.M)
                if names:
                    self.files.append(p)
                for name in ' '.join(names).split():
                    self.add(name.lower())
        self.cache = {}

    def add(self, name):
        if name in ('_', '""'):
            return
        if name.startswith('~'):
            try:
                self.regex.append(re.compile(name[1:]))
            except re.error:
                pass
        elif name.startswith('*.'):
            self.suffix.append(name[1:])
        elif name.startswith('.'):
            self.exact.add(name[1:])
            self.suffix.append(name)
        elif name.endswith('.*'):
            self.prefix.append(name[:-1])
        else:
            self.exact.add(name)

    def __bool__(self):
        return bool(self.exact or self.suffix or self.prefix or self.regex)

    def __contains__(self, host):
        if not self:
            return True
        if host not in self.cache:
            self.cache[host] = (host in self.exact or any(host.endswith(s) for s in self.suffix)
                                or any(host.startswith(p) for p in self.prefix)
                                or any(r.search(host) for r in self.regex))
        return self.cache[host]


# --- bots ------------------------------------------------------------------

def newest_versions(records):
    """Newest Chrome and Firefox with a real share of the traffic (2%+), so a
    few fake future versions can't make every real browser look outdated."""
    agents = Counter(r[UA] for r in records)
    families = defaultdict(Counter)
    for ua, n in agents.items():
        if ua.startswith('Mozilla/') and not BOTS.search(ua):
            m = VERSION.search(ua)
            if m:
                families[m.group(1)][int(m.group(2))] += n
    newest = {}
    for name, versions in families.items():
        total = sum(versions.values())
        common = [v for v, n in versions.items() if n >= 0.02 * total]
        if common:
            newest[name] = max(common)
    return newest


def ua_reason(ua, newest):
    if ua in ('', '-'):
        return 'empty user agent'
    if ua == NO_UA:
        return None
    if BOTS.search(ua) or DECLARED.search(ua):
        return 'bot user agent'
    if not ua.startswith(('Mozilla/', 'Opera/')):
        return 'not a browser'
    if not BROWSER.search(ua):
        return 'fake browser agent'
    m = VERSION.search(ua)
    if m and m.group(1) in newest and int(m.group(2)) < newest[m.group(1)] - OUTDATED:
        return 'outdated browser'
    return None


def classify(records):
    """Why each request is a bot (None for people), and why each flagged IP is."""
    newest = newest_versions(records)
    probe, per_ip, ips = {}, defaultdict(lambda: [0, 0]), {}
    for r in records:
        hit = probe.get(r[PATH])
        if hit is None:
            hit = probe[r[PATH]] = bool(PROBES.search(r[PATH]))
        if hit:
            ips.setdefault(r[IP], 'probing IP')
        c = per_ip[r[IP]]
        c[0] += 1
        if 400 <= r[STATUS] < 500:
            c[1] += 1
    for ip, (n, errors) in per_ip.items():
        if ip not in ips and n >= 20 and errors >= 0.8 * n:
            ips[ip] = 'error-heavy IP'

    agents, reasons = {}, []
    for r in records:
        ua = r[UA]
        why = agents.get(ua, 0)
        if why == 0:
            why = agents[ua] = ua_reason(ua, newest)
        reasons.append(why or ips.get(r[IP]) or ('malformed request' if r[METHOD] == '-' else None))
    return reasons, ips, newest


# --- counting --------------------------------------------------------------

class Stats:
    def __init__(self, records, reasons, filters, bots, pages, only_bots=False):
        recs = []
        self.why = Counter()
        for r, why in zip(records, reasons):
            if filters and not all(r[f] == v for f, v in filters):
                continue
            if pages and r[ASSET]:
                continue
            if why:
                self.why[why] += 1
            if (why is not None) if only_bots else (bots or why is None):
                recs.append(r)
        self.bots = sum(self.why.values())
        self.total = len(recs)
        self.recs = recs
        self.day_status = Counter()

        counters = {name: Counter() for name, _, _ in PANELS[1:]}
        days = defaultdict(lambda: [0, set(), 0])
        self.hours = Counter()
        self.status = Counter()
        self.bytes = 0
        ips = set()
        days_c, urls, data, hosts, sites = (counters['Days'], counters['URLs'], counters['Data'],
                                            counters['Hosts'], counters['Sites'])
        refs, status, notfound, ipc, uas = (counters['Referrers'], counters['Status'], counters['404s'],
                                            counters['IPs'], counters['Agents'])
        for r in recs:
            days_c[r[DAY]] += 1
            urls[r[PATH]] += 1
            data[r[PATH]] += r[BYTES]
            hosts[r[HOST]] += 1
            status[r[STATUS]] += 1
            ipc[r[IP]] += 1
            uas[r[UA]] += 1
            if r[SITE]:
                sites[r[SITE]] += 1
                refs[r[REF]] += 1
            if r[STATUS] == 404:
                notfound[r[PATH]] += 1
            d = days[r[DAY]]
            d[0] += 1
            d[1].add(r[IP])
            d[2] += r[BYTES]
            self.hours[r[DAY], r[HOUR]] += 1
            self.day_status[r[DAY], r[STATUS] // 100] += 1
            self.status[r[STATUS] // 100] += 1
            self.bytes += r[BYTES]
            ips.add(r[IP])
        self.ips = len(ips)
        self.days = {d: (v[0], len(v[1]), v[2]) for d, v in sorted(days.items())}
        self.rows = {}
        for name, _, by_key in PANELS[1:]:
            c = counters[name]
            if name in BYTE_PANELS:
                c = +c          # drop zeros
            self.rows[name] = sorted(c.items()) if by_key else c.most_common()
            self.rows[name + ' total'] = sum(c.values())

    def hourly(self):
        """Requests for every hour from the first to the last one seen."""
        if not self.hours:
            return []
        first, last = min(self.hours), max(self.hours)
        day = datetime.date.fromisoformat(first[0])
        out = []
        while True:
            for h in range(24):
                key = (day.isoformat(), h)
                if key < first:
                    continue
                out.append((key, self.hours.get(key, 0)))
                if key == last:
                    return out
            day += datetime.timedelta(days=1)


# --- drawing helpers -------------------------------------------------------

UNICODE = True
PARTS = ' ▏▎▍▌▋▊▉'
COLUMN = ' ▁▂▃▄▅▆▇█'


def hbar(n, top, width):
    if top <= 0 or width <= 0:
        return ''
    eighths = round(n / top * width * 8)
    if not UNICODE:
        return '#' * max(eighths // 8, 1 if n else 0)
    full, part = divmod(eighths, 8)
    return ('█' * full + (PARTS[part] if part else '')) or ('▏' if n else '')


def columns(values, width):
    """Shrinks a series to at most width columns, summing neighbours."""
    if len(values) <= width:
        return values, 1
    step = -(-len(values) // width)
    return [sum(values[i:i + step]) for i in range(0, len(values), step)], step


def vchart(values, height):
    """Rows of a vertical bar chart, top row first."""
    top = max(values) if values else 0
    if not top:
        return [' ' * len(values)] * height
    rows = []
    for row in range(height - 1, -1, -1):
        line = ''
        for v in values:
            fill = min(max(round(v / top * height * 8) - row * 8, 0), 8)
            line += COLUMN[fill] if UNICODE else ('#' if fill >= 4 else ' ')
        rows.append(line)
    return rows


def human(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} TB'


def label(field, value):
    if value is None or value == '':
        return '(none)'
    return str(value)


def pct(n, total):
    return f'{100 * n / total:5.1f}%' if total else '    - '


def amount(name, n):
    return human(n) if name in BYTE_PANELS else f'{n:,}'


def bot_summary(why, n=3):
    return ', '.join(f'{reason} {c:,}' for reason, c in why.most_common(n))


# --- interactive view ------------------------------------------------------

KEYS = '←→ panel  ↑↓ move  ⏎ filter by row  ⌫ undo filter  / search  b bots  p pages only  r reload  q quit'


class UI:
    def __init__(self, scr, app):
        self.scr = scr
        self.app = app
        self.panel = 0
        self.cursor = defaultdict(int)
        self.offset = defaultdict(int)
        self.search = ''
        self.searching = False
        curses.curs_set(0)
        curses.use_default_colors()
        self.color = {}
        if curses.has_colors():
            for i, (name, fg, bg) in enumerate([('title', curses.COLOR_BLACK, curses.COLOR_CYAN),
                                                 ('bar', curses.COLOR_GREEN, -1),
                                                 ('accent', curses.COLOR_CYAN, -1),
                                                 ('filter', curses.COLOR_YELLOW, -1),
                                                 ('error', curses.COLOR_RED, -1)], 1):
                curses.init_pair(i, fg, bg)
                self.color[name] = curses.color_pair(i)

    def c(self, name):
        return self.color.get(name, 0)

    def put(self, y, x, s, attr=0):
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and x < w:
            try:
                self.scr.addstr(y, x, s[:w - x], attr)
            except (curses.error, ValueError):
                pass

    def rows(self):
        name = PANELS[self.panel][0]
        rows = self.app.stats.rows.get(name, [])
        if self.search:
            s = self.search.lower()
            rows = [r for r in rows if s in label(None, r[0]).lower()]
        return rows

    def run(self):
        while True:
            self.draw()
            try:
                key = self.scr.get_wch()
            except curses.error:
                continue
            if self.searching:
                self.search_key(key)
            elif self.key(key) is False:
                return

    def search_key(self, key):
        if key in ('\n', '\r', curses.KEY_ENTER):
            self.searching = False
        elif key == '\x1b':
            self.searching, self.search = False, ''
        elif key in (curses.KEY_BACKSPACE, '\x7f', '\b'):
            self.search = self.search[:-1]
        elif isinstance(key, str) and key.isprintable():
            self.search += key
        self.cursor[self.panel] = self.offset[self.panel] = 0

    def key(self, key):
        app, p = self.app, self.panel
        n = len(self.rows())
        page = max(self.scr.getmaxyx()[0] - 6, 1)
        if key in ('q', 'Q'):
            return False
        elif key in (curses.KEY_RIGHT, '\t', 'l'):
            self.panel = (p + 1) % len(PANELS)
            self.search = ''
        elif key in (curses.KEY_LEFT, curses.KEY_BTAB, 'h'):
            self.panel = (p - 1) % len(PANELS)
            self.search = ''
        elif isinstance(key, str) and key.isdigit():
            self.panel = (int(key) - 1) % 10
            self.search = ''
        elif key in (curses.KEY_DOWN, 'j'):
            self.cursor[p] = min(self.cursor[p] + 1, n - 1)
        elif key in (curses.KEY_UP, 'k'):
            self.cursor[p] = max(self.cursor[p] - 1, 0)
        elif key in (curses.KEY_NPAGE, ' '):
            self.cursor[p] = min(self.cursor[p] + page, n - 1)
        elif key == curses.KEY_PPAGE:
            self.cursor[p] = max(self.cursor[p] - page, 0)
        elif key in (curses.KEY_HOME, 'g'):
            self.cursor[p] = 0
        elif key in (curses.KEY_END, 'G'):
            self.cursor[p] = n - 1
        elif key in ('\n', '\r', curses.KEY_ENTER) and p and n:
            field = PANELS[p][1]
            value = self.rows()[self.cursor[p]][0]
            app.filters = [(f, v) for f, v in app.filters if f != field] + [(field, value)]
            self.changed()
        elif key in (curses.KEY_BACKSPACE, '\x7f', '\b') and app.filters:
            app.filters.pop()
            self.changed()
        elif key == '\x1b':
            self.search = ''
        elif key == '/' and p:
            self.searching, self.search = True, ''
        elif key == 'b':
            app.bots = not app.bots
            self.changed()
        elif key == 'p':
            app.pages = not app.pages
            self.changed()
        elif key == 'r':
            self.message('reading logs…')
            app.reload()
            self.changed()
        self.cursor[self.panel] = max(self.cursor[self.panel], 0)

    def changed(self):
        self.app.count()
        self.search = ''
        self.cursor.clear()
        self.offset.clear()

    def message(self, text):
        h, w = self.scr.getmaxyx()
        self.put(h - 1, 0, ' ' + text.ljust(w), self.c('title'))
        self.scr.refresh()

    def draw(self):
        scr, app, st = self.scr, self.app, self.app.stats
        scr.erase()
        h, w = scr.getmaxyx()

        what = f' nginx_stats  {app.source}  {st.total:,} requests'
        what += '  (bots included)' if app.bots else f'  ({st.bots:,} bots hidden)'
        if app.pages:
            what += '  pages only'
        self.put(0, 0, what.ljust(w), self.c('title') | curses.A_BOLD)

        x = 1
        for i, (name, _, _) in enumerate(PANELS):
            tab = f' {(i + 1) % 10} {name} ' if i < 10 else f' {name} '
            self.put(1, x, tab, curses.A_REVERSE | curses.A_BOLD if i == self.panel else self.c('accent'))
            x += len(tab) + 1

        line = ''
        if app.filters:
            line = 'filter: ' + '  ›  '.join(f'{FIELD_NAMES[f]}={label(f, v)}' for f, v in app.filters)
        if self.search or self.searching:
            line += ('   ' if line else '') + f'search: {self.search}' + ('▏' if self.searching else '')
        self.put(2, 1, line, self.c('filter'))

        if self.panel == 0:
            self.draw_overview(4, h - 2, w)
        else:
            self.draw_list(4, h - 2, w)

        keys = 'type to search, ⏎ done, esc clear' if self.searching else KEYS
        self.put(h - 1, 0, (' ' + keys).ljust(w), self.c('title'))
        scr.refresh()

    def draw_list(self, top, bottom, w):
        p = self.panel
        name, field, _ = PANELS[p]
        rows = self.rows()
        total = self.app.stats.rows.get(name + ' total', 0)
        if not rows:
            self.put(top, 2, 'nothing here', self.c('accent'))
            return
        height = bottom - top - 1
        self.cursor[p] = min(self.cursor[p], len(rows) - 1)
        if self.cursor[p] < self.offset[p]:
            self.offset[p] = self.cursor[p]
        elif self.cursor[p] >= self.offset[p] + height:
            self.offset[p] = self.cursor[p] - height + 1
        barw = max(min(30, w // 4), 5)
        peak = max(c for _, c in rows)

        unit = 'data' if name in BYTE_PANELS else 'requests'
        self.put(top, 1, f'{unit:>10} {"%":>6}  {"":{barw}}  {name.lower()}'
                 f'   {len(rows):,} rows', curses.A_BOLD)
        for i, (value, n) in enumerate(rows[self.offset[p]:self.offset[p] + height]):
            y = top + 1 + i
            selected = self.offset[p] + i == self.cursor[p]
            attr = curses.A_REVERSE if selected else 0
            text = label(field, value)
            if field == STATUS and value >= 400:
                text_attr = attr | self.c('error')
            else:
                text_attr = attr
            self.put(y, 1, f'{amount(name, n):>10} {pct(n, total)}  ', attr)
            self.put(y, 20, hbar(n, peak, barw).ljust(barw), self.c('bar'))
            self.put(y, 22 + barw, text.ljust(w - 23 - barw) if selected else text, text_attr)

        more = len(rows) - self.offset[p] - height
        if more > 0:
            self.put(bottom, 22 + barw, f'{more:,} more ↓', self.c('accent'))

    def draw_overview(self, top, bottom, w):
        st, app = self.app.stats, self.app
        y = top
        if not st.total:
            self.put(y, 2, 'no requests match', self.c('accent'))
            return
        days = list(st.days)
        period = days[0] if len(days) == 1 else f'{days[0]} → {days[-1]}  ({len(days)} days)'
        invalid = f'{app.bad.total:,}' + ('  (--unparsed: why)' if app.bad.total else '')
        info = [
            ('Requests', f'{st.total:,}', 'Unique IPs', f'{st.ips:,}'),
            ('Data sent', human(st.bytes), 'Period', period),
            ('Files', f'{len(app.files)}', 'Invalid lines', invalid),
        ]
        for a, b, c, d in info:
            self.put(y, 2, a, self.c('accent'))
            self.put(y, 16, b, curses.A_BOLD)
            self.put(y, 34, c, self.c('accent'))
            self.put(y, 49, d, curses.A_BOLD)
            y += 1
        self.put(y, 2, 'Status', self.c('accent'))
        x = 16
        for cls in (2, 3, 4, 5):
            part = f'{cls}xx {pct(st.status.get(cls, 0), st.total).strip()}'
            self.put(y, x, part, self.c('error') if cls >= 4 else curses.A_BOLD)
            x += len(part) + 3
        y += 1
        if st.bots:
            self.put(y, 2, 'Bots', self.c('accent'))
            self.put(y, 16, f'{st.bots:,} {"included" if app.bots else "hidden"}: {bot_summary(st.why)}')
        y += 2

        # requests per hour
        hourly = st.hourly()
        chart_h = min(10, max(bottom - y - 6 - min(len(st.days), 8), 3))
        values, step = columns([n for _, n in hourly], w - 4)
        wide = max(min((w - 4) // len(values), 4), 1)     # few hours: wider bars
        unit = 'hour' if step == 1 else f'{step} hours'
        self.put(y, 2, f'Requests per {unit}', curses.A_BOLD)
        self.put(y, 17 + len(unit), f'peak {max(values):,}', self.c('accent'))
        y += 1
        for row in vchart(values, chart_h):
            self.put(y, 2, ''.join(ch * wide for ch in row), self.c('bar'))
            y += 1
        self.put(y, 2, ('─' if UNICODE else '-') * len(values) * wide, self.c('accent'))
        y += 1
        last = -99
        for i in range(0, len(hourly), step):
            (day, hour), _ = hourly[i]
            col = i // step * wide
            if (col == 0 or hour < step) and col - last > 6:
                self.put(y, 2 + col, day[5:], self.c('accent'))
                last = col
            elif step == 1 and hour % 6 == 0 and col - last > 6:
                self.put(y, 2 + col, f'{hour:02d}h', self.c('accent'))
                last = col
        y += 2

        # per day
        self.put(y, 2, f'{"day":<12}{"requests":>10}{"IPs":>9}{"data":>11}', curses.A_BOLD)
        y += 1
        peak = max(v[0] for v in st.days.values())
        barw = max(min(30, w - 50), 5)
        for day, (n, ips, size) in list(st.days.items())[-max(bottom - y, 1):]:
            self.put(y, 2, f'{day:<12}{n:>10,}{ips:>9,}{human(size):>11}')
            self.put(y, 46, hbar(n, peak, barw), self.c('bar'))
            y += 1


# --- plain text report -----------------------------------------------------

def report(app, top):
    st = app.stats
    tty = sys.stdout.isatty()
    bold = (lambda s: f'\x1b[1m{s}\x1b[0m') if tty else str
    green = (lambda s: f'\x1b[32m{s}\x1b[0m') if tty else str

    print(bold(f'nginx_stats  {app.source}'))
    if app.filters:
        print('filter: ' + '  ›  '.join(f'{FIELD_NAMES[f]}={label(f, v)}' for f, v in app.filters))
    days = list(st.days)
    print(f'{st.total:,} requests · {st.ips:,} unique IPs · {human(st.bytes)} · '
          + (f'{days[0]} → {days[-1]}' if days else 'no days')
          + (' · bots included' if app.bots else f' · {st.bots:,} bots hidden')
          + (' · pages only' if app.pages else '')
          + f' · {app.bad.total:,} invalid lines' + (' (--unparsed: why)' if app.bad.total else ''))
    print('status ' + '  '.join(f'{c}xx {pct(st.status.get(c, 0), st.total).strip()}' for c in (2, 3, 4, 5)))
    if st.bots:
        print(f'bots: {bot_summary(st.why, 8)}')

    print()
    print(bold(f'{"day":<12}{"requests":>10}{"IPs":>9}{"data":>11}'))
    peak = max((v[0] for v in st.days.values()), default=0)
    for day, (n, ips, size) in st.days.items():
        print(f'{day:<12}{n:>10,}{ips:>9,}{human(size):>11}  ' + green(hbar(n, peak, 30)))

    for name, field, by_key in PANELS[2:]:
        rows = st.rows[name][:top]
        if not rows:
            continue
        total = st.rows[name + ' total']
        peak = max(n for _, n in rows)
        print()
        print(bold(f'{name}  ({len(st.rows[name]):,})'))
        for value, n in rows:
            print(f'{amount(name, n):>10} {pct(n, total)}  ' + green(hbar(n, peak, 20).ljust(20))
                  + f'  {label(field, value)}')


def unparsed_report(app):
    bad = app.bad
    files = sorted(((f, g, b) for f, (g, b) in bad.files.items() if b), key=lambda x: -x[2])
    print(f'{bad.total:,} unparsed lines in {len(files)} of {len(bad.files)} files')
    if not bad.total:
        return
    print()
    print(f'{"parsed":>12}{"unparsed":>12}  file')
    for f, good, wrong in files:
        print(f'{good:>12,}{wrong:>12,}  {f}')
    print()
    print(f'expected shape: {EXPECTED}')
    for c, why, sh, where, example in bad.rows(15):
        print()
        print(f'{c:,} lines: {why}')
        print(f'  shape:   {sh}')
        print(f'  files:   {where}')
        print(f'  example: {example[:300]}')


# --- dump for reading by an LLM --------------------------------------------

def dump(app, top, path):
    """Markdown with everything distilled, to paste into an LLM for opinions."""
    st = app.stats
    out = []
    w = out.append

    def cell(v):
        v = label(None, v).replace('|', '\\|').replace('\n', ' ')
        return v if len(v) <= 200 else v[:197] + '...'

    def table(head, rows, text_cols=1):
        w('| ' + ' | '.join(head) + ' |')
        w('|' + '|'.join('---:' if i < len(head) - text_cols else '---' for i in range(len(head))) + '|')
        for r in rows:
            w('| ' + ' | '.join(cell(v) if isinstance(v, str) else f'{v:,}' if isinstance(v, int) else str(v)
                                for v in r) + ' |')
        w('')

    def ranked(rows, total, n=top):
        return [(c, pct(c, total).strip(), v) for v, c in rows[:n]]

    def matches(r):
        return all(r[f] == v for f, v in app.filters) and not (app.pages and r[ASSET])

    days = list(st.days)
    w(f'# nginx access stats: {app.source}')
    w('')
    w(f'Generated {datetime.datetime.now():%Y-%m-%d %H:%M} by nginx_stats from {len(app.files)} log files '
      f'of a small web server hosting several personal and portfolio sites.')
    w('')
    w('- Requests are counted per log line. A request counts as a bot for any of the reasons in the '
      '"How requests were classified" table; everything else counts as people. Browsers faking a current '
      'user agent from an IP that never probed still count as people.')
    w('- ' + ('Bots are included in all tables.' if app.bots else
              f'Bots are left out of the main tables ({st.bots:,} requests); they have their own section.'))
    if app.pages:
        w('- Static files (css, js, images, fonts) are left out.')
    if app.filters:
        w('- Only requests with ' + ', '.join(f'{FIELD_NAMES[f]} = {label(f, v)}' for f, v in app.filters) + '.')
    w('- URLs are paths without query strings. "Sites" and "Referrers" are external referrers only.')
    w(f'- Tables show the top {top} rows; the total number of distinct values is in each heading.')
    w('')

    w('## Summary')
    w('')
    w(f'- Period: {days[0]} to {days[-1]} ({len(days)} day{"s" if len(days) > 1 else ""})' if days else '- Period: none')
    w(f'- Requests: {st.total:,}; unique IPs: {st.ips:,}; data sent: {human(st.bytes)}')
    w('- Status: ' + ', '.join(f'{c}xx {pct(st.status.get(c, 0), st.total).strip()}' for c in (2, 3, 4, 5)))
    w(f'- Log lines that could not be read: {app.bad.total:,} (see the last section)')
    if app.newest:
        w('- Newest browsers in these logs: ' + ', '.join(f'{k} {v}' for k, v in sorted(app.newest.items())))
    w('')

    w('## How requests were classified')
    w('')
    every = st.total + (0 if app.bots else st.bots)
    people = every - st.bots
    table(['requests', '%', 'class', 'meaning'],
          [(people, pct(people, every).strip(), 'people', 'none of the reasons below')]
          + [(c, pct(c, every).strip(), why, REASONS[why]) for why, c in st.why.most_common()], text_cols=2)
    if not st.total:
        return finish(out, path, app)

    w('## Per day')
    w('')
    table(['requests', 'unique IPs', 'data', '4xx', '5xx', 'day'],
          [(n, ips, human(size), st.day_status.get((d, 4), 0), st.day_status.get((d, 5), 0), d)
           for d, (n, ips, size) in st.days.items()])

    w('## Hour of day (all days added up, server local time)')
    w('')
    by_hour = Counter()
    for (_, h), n in st.hours.items():
        by_hour[h] += n
    table(['requests', '%', 'hour'], [(by_hour[h], pct(by_hour[h], st.total).strip(), f'{h:02d}:00') for h in range(24)])

    hosts = defaultdict(lambda: [0, set(), 0, 0, Counter()])
    for r in st.recs:
        h = hosts[r[HOST]]
        h[0] += 1
        h[1].add(r[IP])
        h[2] += r[STATUS] >= 400
        h[3] += r[BYTES]
        if r[STATUS] < 400 and not r[ASSET]:
            h[4][r[PATH]] += 1
    known = {h: v for h, v in hosts.items() if not h or h in app.known}     # '' = format without $host
    unknown = {h: v for h, v in hosts.items() if h and h not in app.known}
    w(f'## Sites hosted ({len(known):,})')
    w('')
    if app.known:
        w(f'Host names found in server_name lines of the nginx config ({len(app.known.files)} files). '
          f'Requests for other names are grouped in the last row and listed in "Unknown host names".')
    else:
        w('No nginx config found, so every host name is listed, including names made up by scanners.')
    w('')
    rows = [(n, len(ips), pct(err, n).strip(), human(size), host or '(host not logged)',
             ', '.join(f'{p} ({c:,})' for p, c in pages.most_common(3)))
            for host, (n, ips, err, size, pages) in sorted(known.items(), key=lambda kv: -kv[1][0])[:top]]
    if unknown:
        n = sum(v[0] for v in unknown.values())
        rows.append((n, len(set().union(*(v[1] for v in unknown.values()))),
                     pct(sum(v[2] for v in unknown.values()), n).strip(), human(sum(v[3] for v in unknown.values())),
                     f'({len(unknown):,} unknown host names)', ''))
    table(['requests', 'unique IPs', 'errors %', 'data', 'host', 'most visited pages'], rows, text_cols=2)

    if app.known:
        # all requests, bots included: this is about what the server answers
        names = defaultdict(lambda: [0, set(), 0, 0])
        for r in app.records:
            if r[HOST] and r[HOST] not in app.known and matches(r):
                v = names[r[HOST]]
                v[0] += 1
                v[1].add(r[IP])
                v[2] += 200 <= r[STATUS] < 300
                v[3] += r[BYTES]
        if names:
            w(f'## Unknown host names ({len(names):,}, bots included)')
            w('')
            w('Host headers that match no server_name: scanners guessing subdomains, the bare server IP, '
              'or old domains. A high 2xx % means nginx served real content for that name '
              '(wildcard DNS plus a block that answers any name).')
            w('')
            table(['requests', 'unique IPs', '2xx %', 'data', 'host'],
                  [(n, len(ips), pct(ok, n).strip(), human(size), host)
                   for host, (n, ips, ok, size) in sorted(names.items(), key=lambda kv: -kv[1][0])[:top]])

    for name, field, _ in PANELS[2:]:
        if name == 'Hosts':
            continue
        rows = st.rows[name]
        if not rows:
            continue
        title = {'Sites': 'Referring sites (external)', 'Referrers': 'Referrers (external, full URL)',
                 'Data': 'Data sent per URL', '404s': 'Not found (404) URLs', 'IPs': 'Client IPs',
                 'Agents': 'User agents'}.get(name, name)
        w(f'## {title} ({len(rows):,})')
        w('')
        if name in BYTE_PANELS:
            urls = dict(st.rows['URLs'])
            table(['data', '%', 'requests', 'url'],
                  [(human(b), pct(b, st.rows[name + ' total']).strip(), urls.get(v, 0), v) for v, b in rows[:top]])
        else:
            table(['requests', '%', FIELD_NAMES[field]], ranked(rows, st.rows[name + ' total']))

    if not app.bots and st.bots:
        bots = Stats(app.records, app.reasons, app.filters, True, app.pages, only_bots=True)
        w(f'## Bots ({bots.total:,} requests, {bots.ips:,} IPs, {human(bots.bytes)})')
        w('')
        w('- Status: ' + ', '.join(f'{c}xx {pct(bots.status.get(c, 0), bots.total).strip()}' for c in (2, 3, 4, 5)))
        w('')
        n = max(top // 2, 10)
        for name, title in (('Agents', 'Bot user agents'), ('URLs', 'URLs bots asked for'),
                            ('404s', 'Not found URLs bots asked for (probes)'), ('Data', 'Data sent to bots per URL')):
            w(f'### {title} ({len(bots.rows[name]):,})')
            w('')
            if name in BYTE_PANELS:
                table(['data', '%', 'url'], [(human(b), pct(b, bots.rows[name + ' total']).strip(), v)
                                             for v, b in bots.rows[name][:n]])
            else:
                field = dict((p[0], p[1]) for p in PANELS)[name]
                table(['requests', '%', FIELD_NAMES[field]], ranked(bots.rows[name], bots.rows[name + ' total'], n))
        w(f'### Bot IPs ({len(bots.rows["IPs"]):,})')
        w('')
        table(['requests', '%', 'ip', 'flagged as'],
              [(c, pct(c, bots.rows['IPs total']).strip(), ip, app.flagged_ips.get(ip, 'by user agent'))
               for ip, c in bots.rows['IPs'][:n]], text_cols=2)
    return finish(out, path, app)


def finish(out, path, app):
    bad = app.bad
    w = out.append
    w('## Log files and unparsed lines')
    w('')
    parsed = sum(g for g, _ in bad.files.values())
    w(f'- {len(bad.files)} files, {parsed:,} lines read, {bad.total:,} could not be read '
      f'({pct(bad.total, parsed + bad.total).strip()}).')
    w(f'- Expected line shape: `{EXPECTED}` '
      '(nginx combined + "$http_x_forwarded_for" + "$host"). Shapes replace values with IP, N (number), '
      '"…" (quoted field), [time] and word.')
    w('')
    files = sorted(((f, g, b) for f, (g, b) in bad.files.items() if b), key=lambda x: -x[2])
    if files:
        w('### Files with unparsed lines')
        w('')
        w('| parsed | unparsed | file |')
        w('|---:|---:|---|')
        for f, good, wrong in files[:40]:
            w(f'| {good:,} | {wrong:,} | {f} |')
        if len(files) > 40:
            w(f'| | | ... {len(files) - 40} more files |')
        w('')
        w('### Unparsed line shapes')
        w('')
        for c, why, sh, where, example in bad.rows(10):
            w(f'- **{c:,} lines**: {why}')
            w(f'  - shape: `{sh}`')
            w(f'  - files: {where}')
            w(f'  - example: `{example[:300].replace("`", "ʼ")}`')
        w('')

    text = '\n'.join(out) + '\n'
    if path == '-':
        sys.stdout.write(text)
    else:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'wrote {path} ({len(text) / 1024:.0f} KB, about {len(text) // 4:,} tokens)', file=sys.stderr)


# --- main ------------------------------------------------------------------

class App:
    def __init__(self, files, days, filters, bots, pages, source, quiet=False):
        self.files, self.days, self.filters = files, days, filters
        self.bots, self.pages, self.source = bots, pages, source
        self.quiet = quiet
        self.known = KnownHosts(NGINX_CONF)
        self.reload()

    def reload(self):
        quiet = self.quiet or not sys.stderr.isatty()
        progress = None if quiet else (lambda f: print(f'reading {f}', file=sys.stderr))
        self.records, self.bad = load(self.files, self.days, progress)
        self.reasons, self.flagged_ips, self.newest = classify(self.records)
        self.quiet = True       # no printing over the interface on reload
        self.count()

    def count(self):
        self.stats = Stats(self.records, self.reasons, self.filters, self.bots, self.pages)


def main():
    ap = argparse.ArgumentParser(
        description='Most accessed URLs, referrers, hosts, IPs... from nginx access logs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='interactive keys:\n  ' + KEYS + '\n\n'
               'Lines in nginx "combined" format, optionally followed by "$http_x_forwarded_for"\n'
               'and/or "$host" (log_format main in _nginx/hifolio.conf). Also read: "common"\n'
               'format, a host name before the IP, \\" escapes and $time_iso8601.')
    ap.add_argument('logs', nargs='*', default=['access'],
                    help='log names in --dir (access, blocked), folders (their access.log*), '
                         'files or globs; several are read together (default: access)')
    ap.add_argument('--dir', default=LOG_DIR, help=f'log folder (default: {LOG_DIR}, or $NGINX_LOG_DIR)')
    ap.add_argument('--days', type=int, help='only the last N days')
    ap.add_argument('--host', help='only this site, e.g. dmtr.org')
    ap.add_argument('--url', help='only this path, e.g. /index.php')
    ap.add_argument('--ip', help='only this client IP')
    ap.add_argument('--status', type=int, help='only this status code, e.g. 404')
    ap.add_argument('--bots', action='store_true', help='include bots (crawlers, scanners, scripts, fake browsers)')
    ap.add_argument('--pages', action='store_true', help='leave out static files (css, js, images, fonts)')
    ap.add_argument('--text', action='store_true', help='print a report instead of the interactive view')
    ap.add_argument('--dump', metavar='FILE', help='write everything distilled as Markdown for an LLM '
                    '(- for stdout) instead of the interactive view')
    ap.add_argument('--unparsed', action='store_true', help='show which lines could not be read, and why')
    ap.add_argument('--top', type=int, help='rows per table (default: 20 in --text, 50 in --dump)')
    args = ap.parse_args()

    files = log_files(args.logs, args.dir)
    if not files:
        sys.exit('no log files found')
    filters = [(f, v) for f, v in ((HOST, args.host and args.host.lower()), (PATH, args.url),
                                   (IP, args.ip), (STATUS, args.status)) if v is not None]
    folders = {os.path.dirname(os.path.realpath(f)) for f in files}
    if len(folders) > 1:
        source = f'{len(files)} files in {len(folders)} folders'
    else:
        name = os.path.basename(files[-1])
        source = f'{name}*' if len(files) > 1 else name
    if args.days:
        source += f'  last {args.days} day' + ('s' if args.days > 1 else '')

    global UNICODE
    locale.setlocale(locale.LC_ALL, '')
    UNICODE = 'UTF' in locale.getpreferredencoding().upper()

    app = App(files, args.days, filters, args.bots, args.pages, source)
    if args.unparsed:
        unparsed_report(app)
        return
    if args.dump:
        dump(app, args.top or 50, args.dump)
        return
    if args.text or not sys.stdout.isatty():
        report(app, args.top or 20)
        return

    os.environ.setdefault('ESCDELAY', '25')
    curses.wrapper(lambda scr: UI(scr, app).run())


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        sys.stderr.close()
