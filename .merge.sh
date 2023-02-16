#!/usr/bin/env bash

basedir="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

for file in $(ls $basedir/rules/*.lsrules); do
  sed -i -e 's|\\/|/|g' $file
  python -mjson.tool $file > /dev/null || ( echo "[${file##*/}]"; exit 1 )
done

shopt -s extglob

rules=$(jq -s 'map(.rules[])' $(ls $basedir/rules/!(all).lsrules) 2>&1 | sed 's/^/  /g')

[[ $rules == *"parse error:"* ]] && echo Syntax error in a lsrules file && exit 1

cat <<EOF > $basedir/rules/all.lsrules
{
  "name": "Little Snitch Rules",
  "description": "Complete rule set from https://github.com/ucomesdag/little-snitch-rules",
  "rules": $rules
}
EOF
