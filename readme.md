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
```

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
| `←` `→` `tab`, `1`…`0` | panels: Overview, Days, URLs, Hosts, Sites, Referrers, Status, 404s, IPs, Agents |
| `↑` `↓` `PgUp` `PgDn` `g` `G` | move |
| `enter` | filter everything by the selected row (a URL, a site, an IP, a day...) |
| `backspace` | undo the last filter |
| `/` | search in the current panel (`esc` clears) |
| `b` | show / hide bots (crawlers, scanners, curl, scripts). Hidden by default |
| `p` | pages only: leave out static files |
| `r` | read the logs again |
| `q` | quit |

Filters stack: `enter` on a URL, then panel 6 (Referrers) shows who links
to that page; `enter` on an IP, then panel 3 shows everything it requested.

Sites and Referrers only count external referrers (not the site linking to
itself).

## Log format

nginx `combined` format, optionally followed by `"$http_x_forwarded_for"`
and/or `"$host"`, which is `log_format main` in `_nginx/hifolio.conf`.
Without `$host` the Hosts panel shows `(none)`.

The scripts from 2009–2021 are in `_old/`.
