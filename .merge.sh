#!/usr/bin/env bash

shopt -s extglob

basedir="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
rules=$(jq -s 'map(.rules[])' $(ls $basedir/rules/!(all).lsrules) | sed 's/^/  /g')

cat <<EOF > $basedir/rules/all.lsrules
{
  "name": "Little Snitch Rules",
  "description": "Complete rule set from https://github.com/ucomesdag/little-snitch-rules",
  "rules": $rules
}
EOF
