#/bin/bash
cd "$(dirname "$0")"

echo 'nginx2'
./nginx2.py

echo 'nginx5'
./nginx5.py

echo 'nginx_sqlite.py'
./nginx_sqlite.py
