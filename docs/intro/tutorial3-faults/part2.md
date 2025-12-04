# Tutorial 3: Testing faults with Revizor (Part 2)

This tutorial picks up where [part 1](part1.md) left off. We will run the fuzzer with the configuration you've created, and see the results.

### Run the fuzzer

With the configuration ready, let's run the fuzzer.

```
$ ./revizor.py fuzz -s base.json -c dbg/tut/2.yaml -n 1000 -i 20 -w .

INFO: [fuzzer] Starting at 12:05:26
66    ( 7%)| Stats: Cls:19/19,In:40,R:19,SF:0,OF:0,Fst:6,CN:60,CT:0,P1:0,CS:0,P2:0,V:0
```

Notice in the statistics that `SF:0,OF:0`—unlike the Spectre V1 campaign, none of our test cases are filtered by the speculation or observation filters since every test case with a page fault exhibits speculation.

Eventually (after a few minutes), Revizor detects a violation:

```
================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:3   | ID:23 |
-----------------------------------------------------------------------------------
^^.^.......^.........^..^.........................^............^ | 627    | 0     |
^^.^...^...^............^.........................^............^ | 0      | 627   |

```

The output is similar to what we saw in the Spectre V1 campaign, so we won't go into the details of reading the violation report again. The key takeaway is that we've successfully detected a contract violation, and the hardware traces show different cache access patterns for the two inputs.

### Validate the violation

As before, we validate the violation by reproducing it:

```
$ ./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml -t ./violation/program.asm -i ./violation/input*.bin
```

The output should be similar to the original:

```
================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:3   | ID:23 |
-----------------------------------------------------------------------------------
^^.^.......^.........^..^.........................^............^ | 627    | 0     |
^^.^...^...^............^.........................^............^ | 0      | 627   |
```

Great! The violation reproduces successfully, confirming it's genuine.

### What's Next?

[Part 3](part3.md) will walk you through minimizing and root-causing the violation.
