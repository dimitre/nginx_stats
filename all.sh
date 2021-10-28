#/bin/bash
cd "$(dirname "$0")"

for d in *.py; do
	echo $d
	python3 ./$d
done
