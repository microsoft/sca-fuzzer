#!/usr/bin/env bash
set -e
trap exit INT

# Test configuration
NUM_INPUTS=100
NUM_PROGS=1000000000  # some large number that is never reached before the timeout
TIMEOUT=7200  # seconds
DEBUG=0


# env checks
if [ -z "${REVIZOR_DIR}" ]; then
    echo "ERROR: REVIZOR_DIR is not set"
    exit 1
fi

if [ -z "${LOGS_DIR}" ]; then
    echo "ERROR: LOGS_DIR is not set"
    exit 1
fi

if [ ! -f "$REVIZOR_DIR/revizor.py" ]; then
    echo "ERROR: Could not find '$REVIZOR_DIR/revizor.py'"
fi

if [ ! -f "$REVIZOR_DIR/src/x86/base.json" ]; then
    echo "ERROR: Could not find '$REVIZOR_DIR/src/x86/base.json'"
fi

# Prepare all files
SCRIPT=$(realpath $0)
SCRIPT_DIR=$(dirname $SCRIPT)

revizor="$REVIZOR_DIR/revizor.py"
instructions="$REVIZOR_DIR/src/x86/base.json"

work_dir="$LOGS_DIR/$(date '+%y.%m.%d.%H.%M.%S')"
mkdir -p "$work_dir"
main_log="$work_dir/log.txt"

# ----------------------------------------------------------------------------
# Templates
# ----------------------------------------------------------------------------
cd $work_dir

cat <<EOF >template.yaml
input_gen_entropy_bits: 24
memory_access_zeroed_bits: 0
inputs_per_class: 2

enable_speculation_filter: true
enable_observation_filter: true
enable_priming: true

program_size: 32
avg_mem_accesses: 16

logging_modes:
  - info
  - stat

instruction_categories:
- BASE-BINARY
- BASE-BITBYTE
- BASE-CMOV
- BASE-COND_BR
- BASE-CONVERT
- BASE-DATAXFER
- BASE-FLAGOP
- BASE-LOGICAL
- BASE-MISC
- BASE-NOP
- BASE-POP
- BASE-PUSH
- BASE-SEMAPHORE
- BASE-SETCC
- BASE-STRINGOP

# these clauses may be re-assigned later
contract_observation_clause: loads+stores+pc
contract_execution_clause:
    - no_speculation
EOF

cp template.yaml template-nsco.yaml
echo "
instruction_blocklist:
- cmpsb
- cmpsd
- cmpsw
- cmpsq
- scasb
- scasd
- scasw
- scasq
- repe cmpsb
- repe cmpsd
- repe cmpsw
- repe cmpsq
- repe scasb
- repe scasd
- repe scasw
- repe scasq
- repne cmpsb
- repne cmpsd
- repne cmpsw
- repne cmpsq
- repne scasb
- repne scasd
- repne scasw
- repne scasq
" >> template-nsco.yaml

cp template-nsco.yaml template-nv1-nsco.yaml
echo "
min_bb_per_function: 1
max_bb_per_function: 1
" >> template-nv1-nsco.yaml

cp template-nv1-nsco.yaml template-all.yaml


# ----------------------------------------------------------------------------
# Functions
# ----------------------------------------------------------------------------
function fuzz() {
    local name=$1
    local expected=$2
    config="$work_dir/${name}.yaml"

    printf "+ $name:\n    detection ...  "
    set +e
    if [ "$DEBUG" -eq "1" ]; then
        echo "python ${revizor} fuzz -s $instructions -c $config -i $NUM_INPUTS -n $NUM_PROGS --timeout $TIMEOUT -w $work_dir/$name"
    fi
    python ${revizor} fuzz -s $instructions -c $config -i $NUM_INPUTS -n $NUM_PROGS --timeout $TIMEOUT -w "$work_dir/$name" &> "$work_dir/$name-log.txt"
    exit_code=$?
    set -e

    if [ $exit_code -eq $expected ]; then
        if grep "ERROR" $work_dir/$name-log.txt &> /dev/null ; then
            printf "\033[33;31merror\033[0m\n"
        elif grep "Errno" $work_dir/$name-log.txt &> /dev/null ; then
            printf "\033[33;31merror\033[0m\n"
        else
            printf "\033[33;32mok\033[0m [%s sec]\n" $(awk '/Duration/{print $2}' $work_dir/$name-log.txt)
        fi
    else
        printf "\033[33;31mfail\033[0m\n"
    fi
}


function reproduce() {
    local name=$1
    local expected=$2

    printf "    reproducing ... "
    set +e
    violation_dir="$work_dir/$name"
    config="$work_dir/${name}-repro.yaml"
    cp "$work_dir/${name}.yaml" $config
    awk "/Input seed:/{print \"input_gen_seed:\", \$4}" $violation_dir/violation-*/report.txt >> $config
    python ${revizor} reproduce -s $instructions -c $config -n $NUM_INPUTS -t $violation_dir/violation-*/program.asm  -i $(ls $violation_dir/violation-*/input*.bin | sort -t _ -k2 -n )  &>> "$work_dir/$name-log.txt"
    exit_code=$?
    set -e

    if [ $exit_code -eq $expected ]; then
        if grep "ERROR" $work_dir/$name-log.txt &> /dev/null ; then
            printf "\033[33;31merror\033[0m\n"
        elif grep "Errno" $work_dir/$name-log.txt &> /dev/null ; then
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
    violation_dir="$work_dir/$name"
    config="$work_dir/${name}-verify.yaml"
    awk "/Input seed:/{print \"input_gen_seed:\", \$4}" $violation_dir/violation-*/report.txt >> $config
    python ${revizor} reproduce -s $instructions -c $config -n $NUM_INPUTS -t $violation_dir/violation-*/program.asm  -i $(ls $violation_dir/violation-*/input*.bin | sort -t _ -k2 -n ) &>> "$work_dir/$name-log.txt"
    exit_code=$?
    set -e

    if [ $exit_code -ne $expected ]; then
        if grep "ERROR" $work_dir/$name-log.txt &> /dev/null ; then
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
    local expected=$2

    fuzz $name $expected
    reproduce $name $expected
    verify $name $expected
}

function fuzz_no_verify() {
    local name=$1
    local expected=$2

    fuzz $name $expected
    reproduce $name $expected

    printf "    no validation\n"
}

# ----------------------------------------------------------------------------
# Measurements
# ----------------------------------------------------------------------------
printf "Starting at $(date '+%H:%M:%S on %d.%m.%Y')\n\n"
cd $work_dir

function spectre_v1() {
    name="spectre-v1"
    cp template-nsco.yaml "${name}.yaml"
    echo "
min_successors_per_bb: 2
min_bb_per_function: 3
max_bb_per_function: 3
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
contract_execution_clause:
    - conditional_br_misprediction
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function spectre_v1_store() {
    name="spectre-v1-store"
    cp template-nsco.yaml "${name}.yaml"
    echo "
min_successors_per_bb: 2
min_bb_per_function: 3
max_bb_per_function: 3
contract_observation_clause: ct-nonspecstore
contract_execution_clause:
    - conditional_br_misprediction
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
contract_observation_clause: loads+stores+pc
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function spectre_v1_var() {
    name="spectre-v1-var"
    cp template-nsco.yaml "${name}.yaml"
    echo "
min_successors_per_bb: 2
min_bb_per_function: 3
max_bb_per_function: 3
contract_execution_clause:
    - conditional_br_misprediction
analyser_subsets_is_violation: false
    " >> "${name}.yaml"
    fuzz_no_verify $name 1
}

function spectre_v4() {
    name="spectre-v4"
    cp template-all.yaml "${name}.yaml"
    echo "
x86_executor_enable_ssbp_patch: false
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
x86_executor_enable_ssbp_patch: true
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function zero_divisor_injection() {
    name="zero-divisor-injection"
    cp template-all.yaml "${name}.yaml"
    echo "
x86_disable_div64: false
    " >> "${name}.yaml"
    fuzz_no_verify $name 1
}

function string_copy_overflow() {
    name="string-copy-overflow"
    cp template.yaml "${name}.yaml"
    echo "
min_bb_per_function: 1
max_bb_per_function: 1
    " >> "${name}.yaml"
    fuzz_no_verify $name 1
}

function exception_delayed_handling() {
    name="exception-delayed-handling"
    cp template-all.yaml "${name}.yaml"
    echo "
actors:
    - main:
        - data_properties:
            - present: False
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
contract_execution_clause:
    - nullinj-fault
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function l1tf_present() {
    name="l1tf-present"
    cp template-all.yaml "${name}.yaml"
    echo "
actors:
    - main:
        - data_properties:
            - present: False
contract_execution_clause:
    - delayed-exception-handling
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
contract_execution_clause:
    - nullinj-fault
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function l1tf_rw() {
    name="l1tf-rw"
    cp template-all.yaml "${name}.yaml"
    echo "
actors:
    - main:
        - data_properties:
            - writable: False
contract_execution_clause:
    - delayed-exception-handling
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
    contract_execution_clause:
        - nullinj-fault
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function l1tf_smap() {
    name="l1tf-smap"
    cp template-all.yaml "${name}.yaml"
    echo "
actors:
    - main:
        - data_properties:
            - user: false
contract_execution_clause:
    - delayed-exception-handling
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
contract_execution_clause:
    - nullinj-fault
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function mds_assist_accessed() {
    name="mds-assist-accessed"
    cp template-all.yaml "${name}.yaml"
    echo "
actors:
    - main:
        - data_properties:
            - accessed: false
contract_execution_clause:
    - delayed-exception-handling
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
contract_execution_clause:
    - nullinj-fault
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function mds_assist_dirty() {
    name="mds-assist-dirty"
    cp template-all.yaml "${name}.yaml"
    echo "
actors:
    - main:
        - data_properties:
            - dirty: false
contract_execution_clause:
    - delayed-exception-handling
    " >> "${name}.yaml"
    cp "${name}.yaml" "${name}-verify.yaml"
    echo "
contract_execution_clause:
    - nullinj-fault
    " >> "${name}-verify.yaml"
    fuzz_and_verify $name 1
}

function l1tf_gp() {
    name="l1tf-gp"
    cp template-all.yaml "${name}.yaml"
    echo "
generator_faults_allowlist:
    - non-canonical-access
contract_execution_clause:
    - delayed-exception-handling
    " >> "${name}.yaml"
    fuzz $name 1
}

function gp_forwarding() {
    name="gp-forwarding"
    cp template-all.yaml "${name}.yaml"
    echo "
generator_faults_allowlist:
    - non-canonical-access
contract_execution_clause:
    - nullinj-fault
    " >> "${name}.yaml"
    fuzz $name 1
}

function div_by_zero_speculation() {
    name="div-by-zero-speculation"
    cp template-all.yaml "${name}.yaml"
    echo "
generator_faults_allowlist:
    - div-by-zero
contract_execution_clause:
    - delayed-exception-handling
    " >> "${name}.yaml"
    fuzz $name 1
}

function div_overflow_speculation() {
    name="div-overflow-speculation"
    cp template-all.yaml "${name}.yaml"
    echo "
generator_faults_allowlist:
    - div-overflow
contract_execution_clause:
    - delayed-exception-handling
    " >> "${name}.yaml"
    fuzz $name 1
}

function tn_opcode_faults() {
    name="TN-opcode-faults"
    cp template-all.yaml "${name}.yaml"
    echo "
generator_faults_allowlist:
    - opcode-undefined
    - breakpoint
    - debug-register
contract_execution_clause:
    - no_speculation
    " >> "${name}.yaml"
    fuzz $name 0
}

spectre_v1
spectre_v1_store
spectre_v1_var
spectre_v4
zero_divisor_injection
string_copy_overflow
exception_delayed_handling
l1tf_present
l1tf_rw
l1tf_smap
mds_assist_accessed
mds_assist_dirty
l1tf_gp
gp_forwarding
div_by_zero_speculation
div_overflow_speculation
tn_opcode_faults
