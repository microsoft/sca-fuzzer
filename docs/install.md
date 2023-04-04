# Installation

**Warning**:
Keep in mind that the Revizor runs randomly-generated code in kernel space.
As you can imagine, things could go wrong.
Make sure you're not running Revizor on an important machine.

## 1. Check Requirements

* Architecture: Revizor supports Intel and AMD x86-64 CPUs.
We also have experimental support for ARM CPUs (see `arm-port` branch) but it is at very early stages, use it on your own peril.

* No virtualization: You will need a bare-metal OS installation.
Testing from inside a VM is not (yet) supported.

* OS: The target machine has to be running Linux v4.15 or later.

## 2. Install Revizor Python Package

If you use `pip`, you can install Revizor with:

```bash
pip install revizor-fuzzer
```

Alternatively, install Revizor from sources:
```bash
# run from the project root directory
make install
```

## 3. Install Revizor Executor (kernel module)

Then build and install the kernel module:

```bash
# building a kernel module require kernel headers
sudo apt-get install linux-headers-$(uname -r)

# get the source code
git clone https://github.com/microsoft/sca-fuzzer.git

# build the executor
cd sca-fuzzer/src/x86/executor
make uninstall  # the command will give an error message, but it's ok!
make clean
make
make install
```

## 4. Download ISA spec

```bash
rvzr download_spec -a x86-64 --extensions BASE SSE SSE2 CLFLUSHOPT CLFSH --outfile base.json
```

## 5. (Optional) System Configuration

For more stable results, disable hyperthreading (there's usually a BIOS option for it).
If you do not disable hyperthreading, you will see a warning every time you invoke Revizor; you can ignore it.

Optionally (and it *really* is optional), you can boot the kernel on a single core by adding `-maxcpus=1` to the boot parameters ([how to add a boot parameter](https://wiki.ubuntu.com/Kernel/KernelBootParameters)).
