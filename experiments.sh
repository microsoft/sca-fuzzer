#!/usr/bin/env bash

if [ -z "${REVIZOR_DIR}" ]; then
    REVIZOR_DIR=$HOME/sca-fuzzer
    echo "WARNING: REVIZOR_DIR is not set. Using default: $REVIZOR_DIR"
fi

if [ ! -f "$REVIZOR_DIR/.env/bin/activate" ]; then
    echo "WARNING: Could not find $REVIZOR_DIR/.env/bin/activate. Using default Python"
else
    source $HOME/sca-fuzzer/.env/bin/activate
fi

# Download ISA spec
if [ ! -f "$REVIZOR_DIR/src/x86/isa_spec/base.json" ]; then
    echo "INFO: Could not find 'base.json'. Downloading it..."
    $REVIZOR_DIR/src/x86/isa_spec/get_spec.py --extensions BASE SSE SSE2 CLFLUSHOPT CLFSH VTX SVM
fi

# Create log direcory
cd $REVIZOR_DIR/src/
mkdir -p $HOME/logs

cat <<EOF >template.yaml
instruction_categories:
  - BASE-BINARY
  - BASE-BITBYTE
  - BASE-CMOV
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
  - BASE-INTERRUPT
  - VTX-VTX
  - SVM-SYSTEM
# - BASE-COND_BR   # conditional branches are excluded to avoid triggering of Spectre V1
# - BASE-STRINGOP  # string ops are excluded to avoid triggering of SCA (reported in Hide&Seek)
x86_disable_div64: true  # 64-bit divisions are excluded to avoid triggering of ZDI (reported in Hide&Seek)
x86_executor_enable_ssbp_patch: true  # SSBP patch is enabled to avoid triggering Spectre V4
program_size: 32
avg_mem_accesses: 8
min_bb_per_function: 1
max_bb_per_function: 1
input_gen_entropy_bits: 24
memory_access_zeroed_bits: 0
inputs_per_class: 2
executor_mode: PP+P
enable_speculation_filter: true
enable_observation_filter: false  # I have a weird feeling about this filter. Let's disable it, just in case
enable_priming: true
ignore_flaky_violations: true
logging_modes:
  - info
  - stat
contract_observation_clause: ct
EOF

function run_fault_on_contracts() {
    fault=$1
    template=$2
    shift
    shift
    contracts=("$@")

    cd $REVIZOR_DIR/src/
    for i in "${contracts[@]}"
    do
        echo ""
        test=$i"_"$fault
        echo "[+] Test name:$test"
        mkdir -p $HOME/logs/$test
        n=0
        while [ -f "$HOME/logs/$test/log$n.txt" ]; do ((n++)); done
        logfile=$HOME/logs/$test/log$n.txt
        echo "[+] Log file: $logfile"
        configfile=$HOME/logs/$test/config.yaml
        cp $template $configfile
        echo "contract_execution_clause:"     >> $configfile
        echo "  - $i"                         >> $configfile
        echo "permitted_faults:"              >> $configfile
        echo "  - $fault"                     >> $configfile
        python ./cli.py fuzz -s x86/isa_spec/base.json -c $configfile -i 100 -n 100000000 --timeout 86400 -w $HOME/logs/$test/violations &> $logfile
    done
}

# null injection could accidentally trigger div-by-zero
# even if the code is instrumented properly
# hence, remove divs from the experiments that test aginst nullinj
cp template.yaml template-no-div.yaml
echo "instruction_blocklist:" >> template-no-div.yaml
echo "  - DIV" >> template-no-div.yaml
echo "  - IDIV" >> template-no-div.yaml

#########################
# PF-present
#########################
fault="PF-present"
clauses=("seq" "ooo" "meltdown" "nullinj-term")
run_fault_on_contracts $fault template-no-div.yaml "${clauses[@]}"

#########################
# PF-writable
#########################
fault="PF-writable"
clauses=("seq" "ooo" "meltdown" "nullinj-term")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"

#########################
# GP-noncanonical
#########################
fault="GP-noncanonical"
clauses=("seq" "ooo" "noncanonical")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"

#########################
# PF-smap
#########################
fault="PF-smap"
clauses=("seq" "ooo" "nullinj-term")
if $(grep "Intel" /proc/cpuinfo > /dev/null); then
    run_fault_on_contracts $fault template-no-div.yaml "${clauses[@]}"
else
    run_fault_on_contracts $fault template.yaml "${clauses[@]}"
fi

#########################
# div-zero
#########################
fault="DE-zero"
clauses=("seq" "ooo" "div-zero")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"

#########################
# div-overflow
#########################
fault="DE-overflow"
clauses=("seq" "ooo" "div-overflow")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"

#########################
# UD
#########################
fault="UD"
clauses=("seq")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"

#########################
# UD-invalid
#########################
if $(grep "Intel" /proc/cpuinfo > /dev/null);; then
    fault="UD-vtx"
else
    fault="UD-svm"
fi
clauses=("seq")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"

#########################
# BP
#########################
fault="BP"
clauses=("seq")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"

#########################
# DB
#########################
fault="DB-instruction"
clauses=("seq")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"

#########################
# assist-accessed
#########################
fault="assist-accessed"
clauses=("seq-assist" "ooo" "nullinj-assist")
if $(grep "Intel" /proc/cpuinfo > /dev/null); then
    run_fault_on_contracts $fault template-no-div.yaml "${clauses[@]}"
else
    run_fault_on_contracts $fault template.yaml "${clauses[@]}"
fi

#########################
# assist-dirty
#########################
fault="assist-dirty"
clauses=("seq-assist" "ooo" "nullinj-assist")
run_fault_on_contracts $fault template.yaml "${clauses[@]}"