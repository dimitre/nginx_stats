#/bin/bash
cd "$(dirname "$0")"

for d in *.py; do
	echo $d
	./$d
done
