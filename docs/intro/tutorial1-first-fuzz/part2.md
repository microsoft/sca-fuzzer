# Tutorial 1: Your First Fuzz (Part 2)

This tutorial picks up where [part1](part1.md) left off. We will run the fuzzer with the configuration you've created, and learn how to read the results.

### Run the Campaign

Let's run the fuzzer with your baseline configuration:

```bash
rvzr fuzz -s base.json -c config.yaml -n 100 -i 50 -w .
```

This command tells Revizor to execute 100 test cases (`-n 100`) with 50 inputs per test case (`-i 50`), using the ISA specification from `base.json` and your configuration file. The `-w .` flag specifies the working directory for saving any violations.

You'll see output similar to this:

```
INFO: [fuzzer] Starting at 14:32:18
100   (100%)| Stats: Cls:50/50,In:100,R:5,SF:0,OF:0,Fst:0,CN:0,CT:0,P1:0,CS:0,P2:0,V:0
================================ No Violations detected ===========================
```

The campaign should complete in under a minute with no violations detected. This is exactly what we expect—our simple arithmetic instructions don't trigger speculation, so the hardware behaves according to the strict sequential contract.

### Interpret the statistics

Let's examine the statistics line to understand what Revizor is reporting:

```
100   (100%)| Stats: Cls:50/50,In:100,R:5,SF:0,OF:0,Fst:0,CN:0,CT:0,P1:0,CS:0,P2:0,V:0
```

#### `100 (100%)`

This part shows we completed all 100 test cases. This number was continuously updated while the fuzzer was running.

#### `Cls:50/50`

These numbers indicate the number of [equivalence classes](../../glossary.md#contract-equivalence-class) formed by the inputs. The first number is the effective classes (> 1 input per class) and the second is the total number of classes.

If you don't understand what all of this means, that's ok. The only important factors are:

- if both numbers are equal (or at least close), and they are also equal to the number of inputs that you've set via `-i` command-line argument: everything is going well.
- if the numbers are different, it means either a misconfiguration or an issue with the input generator. Ensure that `input_per_class` config option is `> 1`.
- if the numbers are equal, but they are both considerably lower than the number of inputs set via `-i`: You're using an overly simple fuzzing configuration, and you're unlikely to find anything with it.

None of the issues above should happen if you're using the config file from this tutorial. If they do, double-check your installation.

#### `R:5`

This is an indirect indicator of the level of noise on the system. More concretely, it is the average sample size used by the executor. It is an adaptive number, which increases when the tool starts to encounter false positive caused by noise.

This number should be relatively small. If you see that it's going above 10-20 range, it is likely because something is polluting the measurements. Consider applying the suggestions [here](../02_install.md#7-optional-system-configuration).

#### `SF:0,OF:0,Fst:0,CN:0,CT:0,P1:0,CS:0,P2:0`

These numbers are the statistics on the effectiveness of various optimizations used by Revizor, such as speculation and observation filtering.

You can ignore these numbers for now, as they are useful only when you're trying to optimize performance of the fuzzer. If you're still curious, though, see the [Fuzzing Statistics Reference](../../ref/runtime-statistic.md).

### Understand what this means

The successful completion of this baseline campaign tells you several things. Your Revizor installation is working correctly—the fuzzer can generate test cases, execute them on your hardware, collect traces, and analyze the results. Your system is stable enough for fuzzing—there's no excessive noise preventing measurement. The kernel module loaded correctly and can execute test programs in the sandbox environment.

!!! success "Setup Verified"
    If you've successfully completed this baseline campaign with no violations, your Revizor installation is ready for real vulnerability detection. You can now proceed to Tutorial 2 with confidence.

!!! warning "Troubleshooting Common Issues"
    If the fuzzer crashes or produces errors, check these common problems:

    **Module not loaded**: Ensure the kernel module is loaded with `lsmod | grep rvzr_executor`. If not, run `cd rvzr/executor_km && make && sudo make install`.

    **Permission denied**: Revizor needs root privileges to access performance counters. Check that your user account on the system has `sudo` privileges.

    **ISA specification missing**: If you see "base.json not found", run `rvzr download_spec` first to download the instruction set specification.

### What's Next?

You've finished the first tutorial. Congrats!

If you're ready to go further and start detecting violations, proceed to [Tutorial 2](../tutorial2-first-vuln/part1.md).

