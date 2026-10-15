# nginx_stats

Most accessed URLs, referrers, sites, IPs, status codes and user agents from
nginx access logs, in an interactive terminal view with bar charts.

Python 3 standard library only: nothing to install. Reads all rotated logs
(`access.log`, `access.log.1`, `access.log.2.gz`...) from `/var/log/nginx`,
so it runs from anywhere, e.g. `/srv/server/nginx_stats`.

```sh
./nginx_stats.py                        # interactive, access.log*
./nginx_stats.py blocked                # blocked.log*
./nginx_stats.py --days 1 --host dmtr.org
./nginx_stats.py --pages                # leave out css, js, images, fonts
./nginx_stats.py --text --top 30        # plain report, for cron or mail
./nginx_stats.py --text --url /lunar/view.php --bots   # who hit this file
./nginx_stats.py --dump stats.md        # everything distilled, to paste into an LLM
./nginx_stats.py --unparsed             # which lines could not be read, and why
```

`--dump FILE` (or `-` for stdout) writes Markdown: summary, how requests were
classified (people / bot reasons), per day, hour of day, each site with its
top pages, host names that match no `server_name` (with their 2xx %), data
per URL, every table at `--top` rows (default 50), what the bots were after,
and the unparsed lines with their likely cause. It explains itself at the
top, so an LLM can read it cold. Filters (`--host`, `--days`, `--pages`...)
apply. It contains IPs and referrer URLs: mind where you paste it.

Several sources are read together, e.g. current logs plus another server's:

```sh
./nginx_stats.py /var/log/nginx /srv/logs/oldserver     # folders: their access.log*
./nginx_stats.py /var/log/nginx/access.log* /srv/logs/oldserver/*.gz
```

Each source is a log name in `--dir` (`access`, `blocked`), a folder, a file
or a glob. A file reached twice is read once. Keep other servers' logs out of
`/var/log/nginx`: logrotate renames and deletes numbered files there.

Default folder: `--dir /path` or `NGINX_LOG_DIR=/path`.

## Interactive keys

| key | |
|---|---|
| `←` `→` `tab`, `1`…`0` | panels: Overview, Days, URLs, Data (bytes per URL), Hosts, Sites, Referrers, Status, 404s, IPs, Agents (last one: arrows) |
| `↑` `↓` `PgUp` `PgDn` `g` `G` | move |
| `enter` | filter everything by the selected row (a URL, a site, an IP, a day...) |
| `backspace` | undo the last filter |
| `/` | search in the current panel (`esc` clears) |
| `b` | show / hide bots (see below). Hidden by default |
| `p` | pages only: leave out static files |
| `r` | read the logs again |
| `q` | quit |

Filters stack: `enter` on a URL, then panel 7 (Referrers) shows who links
to that page; `enter` on an IP, then panel 3 shows everything it requested.

Sites and Referrers only count external referrers (not the site linking to
itself).

## Bots

A request counts as a bot when its user agent says so (bot, crawler, curl,
a `+http` contact link), is not a browser (`WordPress/`, `libredtail-http`),
is a fake browser (`Mozilla/5.0` alone, Chrome without `Safari/`), is a
Chrome/Firefox 18+ versions behind the newest one in the logs, or is empty;
when its IP ever asked for `.env`, `.git`, `wp-login.php`, `phpinfo`... or got
80%+ 4xx over 20+ requests; or when the request line is junk. The Overview,
`--text` and `--dump` show how many requests fell in each reason.

## Known sites

`server_name` lines in `/etc/nginx` and `../_nginx/*.conf` tell real sites
from host names made up by scanners. The dump lists the unknown ones with
their 2xx %: a high one means nginx served a site for an invented name.

## Log format

nginx `combined` format, optionally followed by `"$http_x_forwarded_for"`
and/or `"$host"`, which is `log_format main` in `_nginx/hifolio.conf`. Also
read: `common` (no referrer/agent), a host name before the IP
(`vhost_combined`), `\"` escapes (Apache) and `$time_iso8601`. Anything else
is counted as unparsed: `--unparsed` groups those lines by shape, guesses the
cause (JSON, error.log lines, cut lines, another `log_format`) and shows an
example of each.

## GoAccess

`setup_goaccess.sh` installs GoAccess on Debian (apt), writes `~/.goaccessrc`
with the log format detected from the last line of `access.log`, and checks
that it parses:

```sh
sudo ./setup_goaccess.sh               # or: sudo ./setup_goaccess.sh /other/log/dir
zcat -f /var/log/nginx/access.log* | goaccess -
```

The scripts from 2009–2021 are in `_old/`.
