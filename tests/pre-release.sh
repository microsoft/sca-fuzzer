#!/usr/bin/env bash
set -o errexit -o pipefail -o noclobber -o nounset
trap exit INT

SCRIPT=$(realpath $0)
SCRIPT_DIR=$(dirname $SCRIPT)

# ==================================================================================================
# Read arguments

# check for availability of getopt
getopt --test >/dev/null && true
if [[ $? -ne 4 ]]; then
    echo 'ERROR: getopt is not available'
    exit 1
fi

# List arguments
LONGOPTS=rvzr:,workdir:,verbose
OPTIONS=r:w:v

# Parse output
PARSED=$(getopt --options=$OPTIONS --longoptions=$LONGOPTS --name "$0" -- "$@") || exit 2
eval set -- "$PARSED"

verbose=0
revizor_dir=""
work_dir=""

usage="Usage: $0 [-v] -r <revizor_dir> -w <work_dir>"
while true; do
    case "$1" in
    -v | --verbose)
        verbose=0
        ;;
    -r | --rvzr)
        revizor_dir=$2
        shift
        ;;
    -w | --workdir)
        work_dir=$2
        shift
        ;;
    --)
        shift
        break
        ;;
    esac
    shift
done

# check usage
if [ -z "$revizor_dir" ]; then
    echo "ERROR: revizor_dir is not set"
    echo $usage
    exit 1
fi
if [ -z "$work_dir" ]; then
    echo "ERROR: work_dir is not set"
    echo $usage
    exit 1
fi

# make sure that the directories and required files exist
if [ ! -d "$revizor_dir" ]; then
    echo "ERROR: Could not find '$revizor_dir'"
fi
if [ ! -d "$work_dir" ]; then
    echo "ERROR: Could not find '$work_dir'"
fi
if [ ! -f "$revizor_dir/revizor.py" ]; then
    echo "ERROR: Could not find '$revizor_dir/revizor.py'"
fi
if [ ! -f "$revizor_dir/src/x86/base.json" ]; then
    echo "ERROR: Could not find '$revizor_dir/src/x86/base.json'"
fi

work_dir=$(realpath $work_dir)
work_dir="$work_dir/$(date '+%Y-%m-%d-%H-%M-%S')"

# ==================================================================================================
# Test configuration
NUM_INPUTS=25
NUM_PROGS=1000000000 # some large number that is never reached before the timeout
TIMEOUT=7200         # seconds

# Globals
revizor="$revizor_dir/revizor.py"
instructions="$revizor_dir/src/x86/base.json"
conf_dir="$SCRIPT_DIR/configs/"

# ==================================================================================================
# Functions
function _check_results() {
    # Check the output of the experiment for errors and parse the results

    # arguments
    local log=$1
    local exit_code=$2
    local expected=$3

    # output messages
    fail="\033[33;31mfail\033[0m"
    error="\033[33;31merror\033[0m"
    ok="\033[33;32mok\033[0m"

    # check for errors
    if grep "ERROR" $log &>/dev/null; then
        printf "$error\n"
        return 1
    fi
    if grep "Errno" $log &>/dev/null; then
        printf "$error\n"
        return 1
    fi

    # if no violations were found, the test failed
    if [ $exit_code -ne $expected ]; then
        printf "$fail [exit code %s != %s]\n" "$exit_code" "$expected"
        return 1
    fi

    # parse the output
    duration=$(awk '/Duration/{print $2}' $log)
    length=$(awk '/^Test Cases:/{print $3}' $log)
    printf "$ok [%s sec, %s tc]\n" "$duration" "$length"
    return 0
}

function run() {
    local name=$1

    # remove leftovers from previous runs
    rm -rf $work_dir &>/dev/null || true
    mkdir -p $work_dir

    # check that the configuration file exists
    config="$conf_dir/${name}.yaml"
    if [ ! -f "$config" ]; then
        echo "ERROR: Could not find '$config'"
        exit 1
    fi

    # create a log file
    log="$conf_dir/${name}-log.txt"
    rm $log &>/dev/null || true

    # Print the header
    echo "================================================================================"
    echo "Running test: $name"

    # run the test
    printf "+ Detect ...  "
    set +e
    if [ $verbose -eq 1 ]; then set -x; fi
    python ${revizor} fuzz -s $instructions -c $config -i $NUM_INPUTS -n $NUM_PROGS --timeout $TIMEOUT -w "$work_dir" | tee "$log"
    exit_code=$?
    if [ $verbose -eq 1 ]; then set +x; fi
    set -e

    _check_results $log $exit_code 1
    if [ $? -ne 0 ]; then
        return
    fi

    # move the violation into a dedicated dir
    vdir="$work_dir/violation*"
    if [ -d "$vdir" ]; then
        echo "ERROR: Could not find a violation directory: '$vdir'"
        exit 1
    fi

    # reproduce the violations
    printf "+ Reproduce ...  "
    set +e
    if [ $verbose -eq 1 ]; then set -x; fi
    python ${revizor} reproduce -s $instructions -c $vdir/reproduce.yaml -I $conf_dir -t $vdir/program.asm -i $(ls $vdir/input*.bin) | tee "$log"
    exit_code=$?
    if [ $verbose -eq 1 ]; then set +x; fi
    set -e

    _check_results $log $exit_code 1
    if [ $? -ne 0 ]; then
        return
    fi
}

function reproduce() {
    local name=$1
    local expected=$2

    printf "    reproducing ... "
    set +e
    violation_dir="$conf_dir/$name"
    config="$conf_dir/${name}-repro.yaml"
    cp "$conf_dir/${name}.yaml" $config
    awk "/Input seed:/{print \"input_gen_seed:\", \$4}" $violation_dir/violation-*/report.txt >>$config
    python ${revizor} reproduce -s $instructions -c $config -n $NUM_INPUTS -t $violation_dir/violation-*/program.asm -i $(ls $violation_dir/violation-*/input*.bin | sort -t _ -k2 -n) &>>"$conf_dir/$name-log.txt"
    exit_code=$?
    set -e

    if [ $exit_code -eq $expected ]; then
        if grep "ERROR" $conf_dir/$name-log.txt &>/dev/null; then
            printf "\033[33;31merror\033[0m\n"
        elif grep "Errno" $conf_dir/$name-log.txt &>/dev/null; then
            printf "\033[33;31merror\033[0m\n"
        else
            printf "\033[33;32mok\033[0m\n"
        fi
    else
        printf "\033[33;31mfail\033[0m\n"
    fi
}

function verify() {
    local name=$1
    local expected=$2

    printf "    validating ... "
    set +e
    violation_dir="$conf_dir/$name"
    config="$conf_dir/${name}-verify.yaml"
    awk "/Input seed:/{print \"input_gen_seed:\", \$4}" $violation_dir/violation-*/report.txt >>$config
    python ${revizor} reproduce -s $instructions -c $config -n $NUM_INPUTS -t $violation_dir/violation-*/program.asm -i $(ls $violation_dir/violation-*/input*.bin | sort -t _ -k2 -n) &>>"$conf_dir/$name-log.txt"
    exit_code=$?
    set -e

    if [ $exit_code -ne $expected ]; then
        if grep "ERROR" $conf_dir/$name-log.txt &>/dev/null; then
            printf "\033[33;31merror\033[0m\n"
        else
            printf "\033[33;32mok\033[0m\n"
        fi
    else
        printf "\033[33;31mfail\033[0m\n"
    fi
}

function fuzz_and_verify() {
    local name=$1

    fuzz $name
    reproduce $name $expected
    # verify $name $expected
}

function fuzz_no_verify() {
    local name=$1
    local expected=$2

    fuzz $name $expected
    reproduce $name $expected

    printf "    no validation\n"
}

# ==================================================================================================
# Measurements
printf "Starting at $(date '+%H:%M:%S on %d.%m.%Y')\n\n"

run "v1"
run "v1-store"
run "v1-var"
run "v4"
run "zdi"
run "sco"
run "ooo"
