#!/usr/bin/env bash

basedir="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

for file in $(ls $basedir/rules/*.lsrules); do
  sed -i -e 's|/Users/.*/Applications/|/Applications/|g' -e 's|/Applications/Brew/|/Applications/|g' $file
done

tmp=$(mktemp -d)
bash -c "
cp $basedir/rules/* $tmp/ &&
git stash &>/dev/null &&
git stash drop &>/dev/null &&
git checkout main &>/dev/null &&
cp $tmp/* $basedir/rules/ &&
rm -rf $tmp
"
