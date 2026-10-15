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

# combined format, then optional extra quoted fields. Ours (log_format main):
# ... "$http_user_agent" "$http_x_forwarded_for" "$host"
LINE = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"(.*)')
EXTRA = re.compile(r'"([^"]*)"')
MONTHS = {m: '%02d' % i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}
STATIC = re.compile(r'\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|ogg)$', re.I)
BOTS = re.compile(
    r'bot|crawl|spider|slurp|scan|curl|wget|python|go-http|java/|libwww|perl|ruby|php/|okhttp|axios|'
    r'node-fetch|httpclient|http-client|headless|lighthouse|facebookexternalhit|preview|feed|monitor|'
    r'uptime|zgrab|masscan|nmap|nikto|sqlmap|ahrefs|semrush|mj12|dataprovider|censys|expanse|palo alto|'
    r'^-?$', re.I)

# record fields
IP, DAY, HOUR, METHOD, PATH, STATUS, BYTES, REF, SITE, UA, HOST, BOT, ASSET = range(13)

# name, record field, sort by key instead of count
PANELS = [
    ('Overview', None, False),
    ('Days', DAY, True),
    ('URLs', PATH, False),
    ('Hosts', HOST, False),
    ('Sites', SITE, False),        # external referring sites
    ('Referrers', REF, False),     # external referrers, full url
    ('Status', STATUS, False),
    ('404s', PATH, False),
    ('IPs', IP, False),
    ('Agents', UA, False),
]
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


class Parser:
    def __init__(self):
        self.sites = {}
        self.bots = {}

    def site(self, ref):
        if ref not in self.sites:
            try:
                host = urlsplit(ref).hostname or ''
            except ValueError:
                host = ''
            self.sites[ref] = sys.intern(host[4:] if host.startswith('www.') else host)
        return self.sites[ref]

    def parse(self, line):
        m = LINE.match(line)
        if not m:
            return None
        ip, t, req, status, size, ref, ua, rest = m.groups()
        month = MONTHS.get(t[3:6])
        if not month:
            return None
        day = sys.intern(f'{t[7:11]}-{month}-{t[0:2]}')
        parts = req.split(' ')
        if len(parts) == 3:
            method, uri = parts[0], parts[1]
        else:
            method, uri = '-', req      # junk sent by scanners
        path = sys.intern(uri.split('?', 1)[0])

        # "$http_x_forwarded_for" "$host", or just one of them
        extra = EXTRA.findall(rest)
        host = ''
        if len(extra) >= 2:
            host = extra[-1]
        elif extra and not is_xff(extra[0]):
            host = extra[0]
        host = sys.intern(host.lower())

        site = None
        if ref != '-':
            s = self.site(ref)
            if s and s != (host[4:] if host.startswith('www.') else host):
                site = s
        if ua not in self.bots:
            self.bots[ua] = bool(BOTS.search(ua))
        return (sys.intern(ip), day, int(t[12:14]), sys.intern(method), path, int(status),
                0 if size == '-' else int(size), sys.intern(ref), site, sys.intern(ua), host,
                self.bots[ua], bool(STATIC.search(path)))


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
    parser, records, bad = Parser(), [], 0
    oldest = datetime.datetime.now().timestamp() - (days + 1) * 86400 if days else 0
    for f in files:
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
                    elif line.strip():
                        bad += 1
        except (OSError, EOFError) as e:
            print(f'skipping {f}: {e}', file=sys.stderr)
    if days and records:
        last = datetime.date.fromisoformat(max(r[DAY] for r in records))
        first = (last - datetime.timedelta(days=days - 1)).isoformat()
        records = [r for r in records if r[DAY] >= first]
    return records, bad


# --- counting --------------------------------------------------------------

class Stats:
    def __init__(self, records, filters, bots, pages):
        recs = [r for r in records
                if all(r[f] == v for f, v in filters) and not (pages and r[ASSET])]
        self.bots = sum(1 for r in recs if r[BOT])
        if not bots:
            recs = [r for r in recs if not r[BOT]]
        self.total = len(recs)
        self.recs = recs
        self.day_status = Counter()

        counters = {name: Counter() for name, _, _ in PANELS[1:]}
        days = defaultdict(lambda: [0, set(), 0])
        self.hours = Counter()
        self.status = Counter()
        self.bytes = 0
        ips = set()
        days_c, urls, hosts, sites = counters['Days'], counters['URLs'], counters['Hosts'], counters['Sites']
        refs, status, notfound, ipc, uas = (counters['Referrers'], counters['Status'], counters['404s'],
                                            counters['IPs'], counters['Agents'])
        for r in recs:
            days_c[r[DAY]] += 1
            urls[r[PATH]] += 1
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
            tab = f' {(i + 1) % 10} {name} '
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

        self.put(top, 1, f'{"requests":>10} {"%":>6}  {"":{barw}}  {name.lower()}'
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
            self.put(y, 1, f'{n:>10,} {pct(n, total)}  ', attr)
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
        info = [
            ('Requests', f'{st.total:,}', 'Unique IPs', f'{st.ips:,}'),
            ('Data sent', human(st.bytes), 'Period', period),
            ('Files', f'{len(app.files)}', 'Invalid lines', f'{app.bad:,}'),
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
          + f' · {app.bad:,} invalid lines')
    print('status ' + '  '.join(f'{c}xx {pct(st.status.get(c, 0), st.total).strip()}' for c in (2, 3, 4, 5)))

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
            print(f'{n:>10,} {pct(n, total)}  ' + green(hbar(n, peak, 20).ljust(20)) + f'  {label(field, value)}')


# --- dump for reading by an LLM --------------------------------------------

def dump(app, top, path):
    """Markdown with everything distilled, to paste into an LLM for opinions."""
    st = app.stats
    out = []
    w = out.append

    def cell(v):
        v = label(None, v).replace('|', '\\|')
        return v if len(v) <= 160 else v[:157] + '...'

    def table(head, rows, text_cols=1):
        w('| ' + ' | '.join(head) + ' |')
        w('|' + '|'.join('---:' if i < len(head) - text_cols else '---' for i in range(len(head))) + '|')
        for r in rows:
            w('| ' + ' | '.join(cell(v) if isinstance(v, str) else f'{v:,}' if isinstance(v, int) else str(v)
                                for v in r) + ' |')
        w('')

    def ranked(rows, total, n=top):
        return [(c, pct(c, total).strip(), v) for v, c in rows[:n]]

    days = list(st.days)
    w(f'# nginx access stats: {app.source}')
    w('')
    w(f'Generated {datetime.datetime.now():%Y-%m-%d %H:%M} by nginx_stats from {len(app.files)} log files '
      f'of a small web server hosting several personal and portfolio sites.')
    w('')
    w('- Requests are counted per log line. Bots (crawlers, scanners, curl, scripts, empty user agent) '
      'are detected by user-agent keywords; browsers faking their agent count as people.')
    w('- ' + ('Bots are included in all tables.' if app.bots else
              f'Bots are left out of the main tables ({st.bots:,} requests); they have their own section at the end.'))
    if app.pages:
        w('- Static files (css, js, images, fonts) are left out.')
    if app.filters:
        w('- Only requests with ' + ', '.join(f'{FIELD_NAMES[f]} = {label(f, v)}' for f, v in app.filters) + '.')
    w('- URLs are paths without query strings. "Sites" and "Referrers" are external referrers only.')
    w(f'- Tables show the top {top} rows; the total number of distinct values is in each heading.')
    w('')

    w('## Summary')
    w('')
    w(f'- Period: {days[0]} to {days[-1]} ({len(days)} days)' if days else '- Period: none')
    w(f'- Requests: {st.total:,}; unique IPs: {st.ips:,}; data sent: {human(st.bytes)}')
    w('- Status: ' + ', '.join(f'{c}xx {pct(st.status.get(c, 0), st.total).strip()}' for c in (2, 3, 4, 5)))
    w(f'- Unparseable log lines: {app.bad:,}')
    w('')
    if not st.total:
        return finish(out, path)

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

    w(f'## Sites hosted ({len(st.rows["Hosts"]):,})')
    w('')
    hosts = defaultdict(lambda: [0, set(), 0, 0, Counter()])
    for r in st.recs:
        h = hosts[r[HOST]]
        h[0] += 1
        h[1].add(r[IP])
        h[2] += r[STATUS] >= 400
        h[3] += r[BYTES]
        if r[STATUS] < 400 and not r[ASSET]:
            h[4][r[PATH]] += 1
    rows = sorted(hosts.items(), key=lambda kv: -kv[1][0])[:top]
    table(['requests', 'unique IPs', 'errors %', 'data', 'host', 'most visited pages'],
          [(n, len(ips), pct(err, n).strip(), human(size), host,
            ', '.join(f'{p} ({c:,})' for p, c in pages.most_common(3)))
           for host, (n, ips, err, size, pages) in rows], text_cols=2)

    for name, field, _ in PANELS[2:]:
        if name == 'Hosts':
            continue
        rows = st.rows[name]
        if not rows:
            continue
        title = {'Sites': 'Referring sites (external)', 'Referrers': 'Referrers (external, full URL)',
                 '404s': 'Not found (404) URLs', 'IPs': 'Client IPs', 'Agents': 'User agents'}.get(name, name)
        w(f'## {title} ({len(rows):,})')
        w('')
        table(['requests', '%', FIELD_NAMES[field]], ranked(rows, st.rows[name + ' total']))

    if not app.bots and st.bots:
        bots = Stats(app.records, app.filters + [(BOT, True)], True, app.pages)
        w(f'## Bots ({bots.total:,} requests, {bots.ips:,} IPs)')
        w('')
        w('- Status: ' + ', '.join(f'{c}xx {pct(bots.status.get(c, 0), bots.total).strip()}' for c in (2, 3, 4, 5)))
        w('')
        n = max(top // 2, 10)
        for name, title in (('Agents', 'Bot user agents'), ('URLs', 'URLs bots asked for'),
                            ('404s', 'Not found URLs bots asked for (probes)'), ('IPs', 'Bot IPs')):
            w(f'### {title} ({len(bots.rows[name]):,})')
            w('')
            table(['requests', '%', FIELD_NAMES[PANELS[[p[0] for p in PANELS].index(name)][1]]],
                  ranked(bots.rows[name], bots.rows[name + ' total'], n))
    return finish(out, path)


def finish(lines, path):
    text = '\n'.join(lines) + '\n'
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
        self.reload()

    def reload(self):
        quiet = self.quiet or not sys.stderr.isatty()
        progress = None if quiet else (lambda f: print(f'reading {f}', file=sys.stderr))
        self.records, self.bad = load(self.files, self.days, progress)
        self.quiet = True       # no printing over the interface on reload
        self.count()

    def count(self):
        self.stats = Stats(self.records, self.filters, self.bots, self.pages)


def main():
    ap = argparse.ArgumentParser(
        description='Most accessed URLs, referrers, hosts, IPs... from nginx access logs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='interactive keys:\n  ' + KEYS + '\n\n'
               'Lines must be in nginx "combined" format, optionally followed by\n'
               '"$http_x_forwarded_for" and/or "$host" (log_format main in _nginx/hifolio.conf).')
    ap.add_argument('logs', nargs='*', default=['access'],
                    help='log names in --dir (access, blocked), folders (their access.log*), '
                         'files or globs; several are read together (default: access)')
    ap.add_argument('--dir', default=LOG_DIR, help=f'log folder (default: {LOG_DIR}, or $NGINX_LOG_DIR)')
    ap.add_argument('--days', type=int, help='only the last N days')
    ap.add_argument('--host', help='only this site, e.g. dmtr.org')
    ap.add_argument('--url', help='only this path, e.g. /index.php')
    ap.add_argument('--ip', help='only this client IP')
    ap.add_argument('--status', type=int, help='only this status code, e.g. 404')
    ap.add_argument('--bots', action='store_true', help='include crawlers, scanners and scripts')
    ap.add_argument('--pages', action='store_true', help='leave out static files (css, js, images, fonts)')
    ap.add_argument('--text', action='store_true', help='print a report instead of the interactive view')
    ap.add_argument('--dump', metavar='FILE', help='write everything distilled as Markdown for an LLM '
                    '(- for stdout) instead of the interactive view')
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
