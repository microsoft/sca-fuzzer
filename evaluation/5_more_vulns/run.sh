#!/usr/bin/env bash
set -e

if [ -z "${REVIZOR_DIR}" ]; then
    echo "Env. variable REVIZOR_DIR must be set!"
    exit 1
fi
SCRIPT=$(realpath $0)
SCRIPT_DIR=$(dirname $SCRIPT)

instructions='instruction_sets/x86/base.xml'
config="$SCRIPT_DIR/config.yaml"
cd "$REVIZOR_DIR" || exit

function runtest() {
    local name=$1
    local tmpl=$2

    case="$SCRIPT_DIR/$name"
    echo $case
    echo "" > results.txt

    for i in $(seq 0 99); do
        sed -e "s:@seed@:$RANDOM:g" $SCRIPT_DIR/$tmpl > $config
        for j in $(seq 2 2 64) 128 256 512 1024 2048 4096 ; do
            ./cli.py fuzz -s $instructions -t $case -i $j -c $config > tmp.log 2>&1
            if grep "Violations de" tmp.log -q ; then
                echo "$j" >> results.txt
                #echo $j
                break
            fi
        done
    done

    cat results.txt | sort -n | awk '
          BEGIN {
            c = 0;
            sum = 0;
          }
          $1 ~ /^(\-)?[0-9]+(\.[0-9]*)?$/ {
            a[c++] = $1;
            sum += $1;
          }
          END {
            ave = sum / c;
            if( (c % 2) == 1 ) {
              median = a[ int(c/2) ];
            } else {
              median = ( a[c/2] + a[c/2-1] ) / 2;
            }
            OFS="\t";
            print "Sum", "Count", "Ave", "Med", "Min", "Max"
            print sum, c, ave, median, a[0], a[c-1];
          }
        '
}

for name in "spectre_v1.asm" "spectre_v1.1.asm" "spectre_v2.asm" "spectre_v4.asm" "spectre_v5.asm"; do
    runtest $name spectre.yaml.tmpl
done

for name in "mds-lfb.asm" "mds-sb.asm"; do
    runtest $name mds.yaml.tmpl
done

cd - || exit
