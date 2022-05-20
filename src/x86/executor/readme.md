# Install
Tested on Linux v5.6.6-300 and v5.6.13-100.
No guarantees about other versions.

To build the executor, run:

```
make uninstall
make clean
make
make install
```

# Using the executor

Use the Revizor CLI (`src/cli.py`).
This executor is not meant to be used standalone.

On your own peril, you could try using it directly, through the `/sys/x86_executor/` pseudo file system.
You can find an example of how to use it in `src/x86/tests/run.bats`.
But I promise you, there will come a point when your machine will crash or hang.
Better not.
