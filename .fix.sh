#!/usr/bin/env bash

basedir="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

echo "Checking process paths in \"lsrules\" files"
echo "----------------------------------------------------------------------------"

IFS=$'\n'
for file in $(ls $basedir/rules/*.lsrules); do

  for process in $(cat $file | jq -r .rules[].process); do
    if [ "$process" != "any" ] && [ ! -e ${process#script.} ]; then
      new_process="$(ls $(echo ${process#script.} | sed 's|[0-9\.\_-]\+|*|g') 2>/dev/null)"
      if [ "$new_process" != "" ] && [ -e $new_process ]; then
        [[ $process == "script."* ]] && new_process="script.$new_process"
        updated="$updated$process >> $new_process\n"
        sed -i "s|$process|$new_process|g" $file
      else
        notfound="$notfound$process\n"
      fi
    fi
  done

  for via in $(cat $file | jq -r .rules[].process); do
    if [ "$via" != "any" ] && [ ! -e ${via#script.} ]; then
      new_via="$(ls $(echo ${via#script.} | sed 's|[0-9\.\_-]\+|*|g') 2>/dev/null)"
      if [ "$new_via" != "" ] && [ -e $new_via ]; then
        [[ $via == "script."* ]] && new_via="script.$new_via"
        updated="$updated$via >> $new_via\n"
        sed -i "s|$via|$new_via|g" $file
      else
        notfound="$notfound$via\n"
      fi
    fi
  done




done

if [ ! -x $updated ]; then
  echo "Updated:$(sort <(echo -e $updated) | uniq | awk '{print "        ",$0}')"
  echo "----------------------------------------------------------------------------"
fi

if [ ! -x $notfound ]; then
  echo "Not found:$(sort <(echo -e $notfound) | uniq | awk '{print "        ",$0}')"
  echo "----------------------------------------------------------------------------"
fi
