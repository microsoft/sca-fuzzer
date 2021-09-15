#!/usr/bin/awk -f

/Test Cases:/ {
    num_test_cases=$3;
}

/Inputs per test/ {
    inputs=$5;
}

/Patterns:/ {
    num_patterns=$2;
}

/Fully covered:/ {
    num_covered=$3;
}

/Longest uncovered:/ {
    longest_uncovered=$3;
}

/Total Cls:/ {
    total_cls=$3;
}

/Effective Cls:/ {
    effective_cls=$3;
}

/Duration:/ {
    duration=$2;
}

/Finished/ {
    printf "%s, %d, %d, %d, %d, %d, %d, %d, %d\n", name, num_test_cases, duration, inputs, total_cls, effective_cls, num_patterns, num_covered, longest_uncovered;
}