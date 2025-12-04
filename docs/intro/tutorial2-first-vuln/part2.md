# Tutorial 2: Detecting Your First Vulnerability (Part 2)

This tutorial picks up where [part 1](part1.md) left off. We will run the fuzzer with the configuration you've created, and see the results.

### Run the fuzzer

Now we're ready to start fuzzing. Run Revizor with the following command:

```
./revizor.py fuzz -s base.json -c config.yaml -n 1000 -i 10 -w .
```

This command tells Revizor to run 1000 test cases (`-n 1000`), with 10 inputs per test case (`-i 10`), using the ISA specification from `base.json` (`-s`) and our configuration file (`-c`). The `-w .` flag tells Revizor to save any violations it finds to the current directory.

As the fuzzer runs, you'll see a continuously updating progress line:

```
50    ( 5%)| Stats: Cls:10/10,In:20,R:7,SF:38,OF:6,Fst:6,CN:0,CT:0,P1:0,CS:0,P2:0,V:0
```

### View the detected violation

After a minute or so, you should see a violation.
It will be reported in a format similar to this:

```
================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:4   | ID:14 |
-----------------------------------------------------------------------------------
^......^...^........^.................^...........^............. | 626    | 0     |
^......^...^........^........................................... | 1      | 18    |
^^.....^...^........^....^...................................... | 0      | 609   |

```

Excellent! We've successfully detected a contract violation. Let's understand what this violation report is telling us.


The report shows us the violation details in a table format. The header row displays the input IDs that triggered the violation—in this case, inputs 4 and 14:

`| ID:4   | ID:14 |`

These are two inputs from our test case that the contract predicted would behave identically, but the hardware traces show they behaved differently.

The three rows below show the different hardware traces that were observed:

```
^......^...^........^.................^...........^.............
^......^...^........^...........................................
^^.....^...^........^....^......................................
```

Each row represents a distinct cache access pattern, visualized as a bitmap where `^` marks an accessed cache line and `.` marks an untouched cache line. We're using Prime+Probe cache side channel measurements (default), so each position in the bitmap corresponds to one of the 64 cache sets in the L1D cache. (A cache set is a group of cache lines that compete for the same position in the cache—when the CPU accesses memory at a particular address, the data goes into a specific cache set determined by the address bits.)

For example, the first trace reads like this:

```
Cache Set 0 accessed
|          Cache Set 11 accessed
|          |                          Cache set 38 accessed
|          |                          |
^......^...^........^.................^...........^.............
       |            |                             |
       |            |                             Cache Set 50 accessed
       |            Cache Set 20 accessed
       Cache Set 7 accessed
```

Finally, the numbers in the columns tell us how often each trace appeared for each input:

```
... | 626    | 0     |
... | 1      | 18    |
... | 0      | 609   |
```

Looking at the first hardware trace we see it appeared 626 times for input 4 but never for input 14. The third trace shows the opposite pattern—0 times for input 4 but 609 times for input 14. This clear separation in the distributions confirms this is a genuine violation, not random noise.

What we're seeing is a data-dependent cache access pattern. The test case accessed different cache lines depending on the input data, creating an observable side channel. We don't know yet what caused this channel, but we can already tell that it's likely to be caused by speculation; non-speculative cache accesses are permitted by our reference contract, so they wouldn't be reported as violations.

For more details on interpreting violation reports, see [How to Interpret Violation Results](../../howto/interpret-results.md).

### Violation Artifact

The artifact for this violation is stored in a directory named `violation-<timestamp>`:

```bash
$ ls -l violation-251203-103338
input_0000.bin  input_0004.bin  input_0008.bin  input_0012.bin  input_0016.bin  minimize.yaml    reproduce.yaml
input_0001.bin  input_0005.bin  input_0009.bin  input_0013.bin  input_0017.bin  org-config.yaml
input_0002.bin  input_0006.bin  input_0010.bin  input_0014.bin  input_0018.bin  program.asm
input_0003.bin  input_0007.bin  input_0011.bin  input_0015.bin  input_0019.bin  report.txt
```

The `program.asm` file holds the test case program that triggered the violation. The `input_*.bin` files contain the input sequence that exposed the leak. The `report.txt` file provides additional details including hardware and contract traces. The configuration files include `org-config.yaml` (the original configuration), `reproduce.yaml` (for reproducing the violation), and `minimize.yaml` (for test case minimization).

### Validate the violation

Let's verify this violation is genuine and reproducible. First, we'll move the violation artifacts to a simpler path:

```bash
mv violation-251203-103338 ./violation
```

Now we'll reproduce the violation using the saved artifacts:

```bash
./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml -t ./violation/program.asm -i ./violation/input*.bin
```

If the violation is genuine, we should see Revizor report it again:

```
================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:4   | ID:14 |
-----------------------------------------------------------------------------------
^......^...^........^.................^...........^............. | 626    | 0     |
^......^...^........^........................................... | 1      | 20    |
^^.....^...^........^....^...................................... | 0      | 607   |
```

Perfect! The hardware traces are roughly the same as before, confirming this is a stable, reproducible violation.

!!! tip "Dealing with False Positives"
    In most cases, violations are genuine. However, if you're on a high-noise system, you might occasionally see non-reproducible violations. If this happens, adjust the noise tolerance by increasing `analyser_stat_threshold` or `executor_sample_sizes` in your configuration file (see the [Configuration Reference](../../ref/config.md) for details), then rerun the fuzzer. Also, consider trying to mitigate the noise, for example by disabling hyperthreading or by turning prefetchers off.

### What's Next?

[Part 3](part3.md) will walk you through minimizing and root-causing the violation.
