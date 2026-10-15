#!/bin/bash
# Installs GoAccess on Debian and configures it for our nginx logs.
#
#   sudo ./setup_goaccess.sh              # logs in /var/log/nginx
#   sudo ./setup_goaccess.sh /other/dir
#
# Safe to run again: it only rewrites ~/.goaccessrc (backed up first if it changed).

set -euo pipefail

LOG_DIR="${1:-/var/log/nginx}"
LOG="$LOG_DIR/access.log"

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root: sudo $0 $*" >&2
	exit 1
fi

# config goes to the home of whoever called sudo (root if run as root)
USER_NAME="${SUDO_USER:-root}"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
RC="$USER_HOME/.goaccessrc"

echo "== installing goaccess"
apt-get update -q
apt-get install -y -q goaccess
goaccess --version | head -1

# log_format main is combined + "$http_x_forwarded_for" "$host".
# Pick the GoAccess format from the quoted fields in a real line, so it also
# works on servers using plain combined or only one of the extra fields.
echo "== detecting log format from $LOG"
COMBINED='%h - %e [%d:%t %^] "%r" %s %b "%R" "%u"'
FORMAT="$COMBINED \"%^\" \"%v\""
if [ -s "$LOG" ]; then
	LINE="$(tail -n 1 "$LOG")"
	QUOTES="$(printf '%s' "$LINE" | tr -cd '"' | wc -c)"
	LAST="$(printf '%s' "$LINE" | sed -E 's/.*"([^"]*)"[[:space:]]*$/\1/')"
	case $((QUOTES / 2)) in
		3) FORMAT="$COMBINED"; echo "plain combined (no host)" ;;
		4)
			# x-forwarded-for is "-" or IPs (v4 digits and dots, v6 has colons)
			if printf '%s' "$LAST" | grep -Eq '^(-|[0-9., ]+|[0-9a-fA-F.:, ]*:[0-9a-fA-F.:, ]*)$'; then
				FORMAT="$COMBINED \"%^\""; echo "combined + x_forwarded_for (no host)"
			else
				FORMAT="$COMBINED \"%v\""; echo "combined + host"
			fi ;;
		5) echo "combined + x_forwarded_for + host (log_format main)" ;;
		*) echo "unexpected line, using log_format main: $LINE" >&2 ;;
	esac
else
	echo "$LOG is empty or missing, using log_format main"
fi

NEW_RC="$(cat <<EOF
# written by nginx_stats/setup_goaccess.sh
log-format $FORMAT
date-format %d/%b/%Y
time-format %T
ignore-crawlers true
EOF
)"

echo "== writing $RC"
if [ -f "$RC" ] && [ "$(cat "$RC")" != "$NEW_RC" ]; then
	cp "$RC" "$RC.bak"
	echo "previous config saved as $RC.bak"
fi
printf '%s\n' "$NEW_RC" > "$RC"
chown "$USER_NAME": "$RC"

if [ "$USER_NAME" != root ] && ! id -nG "$USER_NAME" | grep -qw adm; then
	usermod -aG adm "$USER_NAME"
	echo "added $USER_NAME to group adm (can read the logs; log in again to take effect)"
fi

echo "== test run"
if [ -s "$LOG" ]; then
	OUT="$(mktemp --suffix=.json)"
	goaccess "$LOG" -p "$RC" -o "$OUT" >/dev/null 2>&1 || true
	TOTAL="$(grep -o '"total_requests": *[0-9]*' "$OUT" | head -1 | grep -o '[0-9]*$' || echo 0)"
	FAILED="$(grep -o '"failed_requests": *[0-9]*' "$OUT" | head -1 | grep -o '[0-9]*$' || echo '?')"
	rm -f "$OUT"
	echo "parsed $TOTAL requests, $FAILED failed"
	if [ "${TOTAL:-0}" -eq 0 ]; then
		echo "nothing parsed: check the log-format line in $RC against: tail -1 $LOG" >&2
	fi
fi

cat <<EOF

== done. Usage:
  goaccess $LOG                                         # today, interactive
  zcat -f $LOG_DIR/access.log* | goaccess -                 # all rotated logs
  zcat -f $LOG_DIR/access.log* | grep '"dmtr.org"\$' | goaccess -   # one site
  zcat -f $LOG_DIR/blocked.log* | goaccess -                # blocked requests
  zcat -f $LOG_DIR/access.log* | goaccess - -o /tmp/report.html     # HTML report
Keys: Tab / 1-9 panels, o or Enter expand, s sort, / search, q quit.
EOF
