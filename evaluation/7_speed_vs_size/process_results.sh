#!/usr/bin/env bash
set -e

results=$1
sample_size=$2

if [ -z "${results}" ] || [ -z "${sample_size}" ] ; then
    echo "Usage: ./process_results.sh <csv file with results> <sample size>"
    exit 1
fi


datamash -t, groupby 1,2,3,4,5,8 mean 6 pstdev 6  mean 7 pstdev 7 mean 9 mean 10 < $results |
    awk 'BEGIN{
        FS=",";
        printf "%-10s %-4s %-4s %-4s %-4s %-5s  %-7s %-7s||%-13s||%-13s\n", "", "", "", "", "", "", "", "", "Test Cases", "Duration";
        format="%-10s|%-4s|%-4s|%-4s|%-4s|%-5s||%-7s|%-7s||%-6s|%-6s||%-6s|%-6s\n";
        printf format, "Name", "Size", "Mem", "BBs", "Entr", "Inpts", "Tot Cls", "Eff Cls", "low", "up", "low", "up";
        printf format, "----------", "----", "----", "----", "----", "----", "-------", "-------", "------", "------", "------", "------";
    }

    //{
        name=$1;
        size=$2;
        mem_accesses=$3;
        blocks=$4;
        entropy=$5;
        inputs=$6;
        total_cls=$11;
        eff_cls=$12;

        tc_low= $7 - (1.96 * $8 / sqrt(sample_size));
        tc_high=$7 + (1.96 * $8 / sqrt(sample_size));
        duration_low= $9 - (1.96 * $10 / sqrt(sample_size));
        duration_high=$9 + (1.96 * $10 / sqrt(sample_size));

        format="%-10s|%-4s|%-4s|%-4s|%-4d|%-5.0f||%-7.1f|%-7.1f||%-6.1f|%-6.1f||%-6.1f|%-6.1f\n";
        printf format, name, size, mem_accesses, blocks, entropy, inputs, total_cls, eff_cls, tc_low, tc_high, duration_low, duration_high;
    }' sample_size=$sample_size
