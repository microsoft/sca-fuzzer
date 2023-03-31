## Requirements & Dependencies

### 1. Hardware Requirements

Revizor supports Intel and AMD x86-64 CPUs.

We also have experimental support for ARM CPUs (see `arm-port` branch) but use it on your own peril.

### 2. Software Requirements

* OS and virtualization:
You will need a Linux bare-metal installation.
Other operating systems and testing from inside a VM is not (yet) supported.

* Linux kernel: v4.15 or later.
Older kernels may or may not work - we have not tested on them.

To check your current Linux kernel version:
```shell
cat /proc/version
```

* Linux Kernel Headers

```shell
# On Ubuntu
sudo apt-get install linux-headers-$(uname -r)
```

* [Python 3.9+](https://www.python.org/downloads/)

If your distribution has an older python by default, the best practice is to use a virtual environment.
```shell
# On Ubuntu 18
sudo apt install python3.9 python3.9-distutils

python3.9 -m venv venv

# re-run this command every time you open a new terminal session
source ./venv/bin/activate
```

* [Unicorn 1.0.2+](https://www.unicorn-engine.org/docs/).
Preferably, use version 1.0.2 or 1.0.3 as they seem to be currently the most stable.
We've encountered several bugs when using the most recent version 2.0.


```shell
sudo apt install unicorn
```

* Python bindings to Unicorn

```shell
pip3 install --user unicorn

# OR, if installed from sources
cd bindings/python
sudo make install

# if you're using venv, copy the installation (the paths in your installation may differ)
cp -r /usr/local/lib/python3.6/site-packages/unicorn-1.0.3-py3.8.egg/unicorn/ venv/lib64/python3.9/site-packages/
```

* Python packages `pyyaml`, `types-pyyaml`, `numpy`:

```shell
pip3 install --user pyyaml types-pyyaml numpy  # skip --user if you're installing in venv
```

### 3. Software Requirements for Revizor Development

Tests:
* [Bash Automated Testing System](https://bats-core.readthedocs.io/en/latest/index.html)
* [mypy](https://mypy.readthedocs.io/en/latest/getting_started.html#installing-and-running-mypy)
* [flake8](https://flake8.pycqa.org/en/latest/index.html)


Documentation:
* [pdoc3](https://pypi.org/project/pdoc3/)

### 4. (Optional) System Configuration

For more stable results, disable hyperthreading (there's usually a BIOS option for it).
If you do not disable hyperthreading, you will see a warning every time you invoke Revizor; you can ignore it.

Optionally (and it *really* is optional), you can boot the kernel on a single core by adding `-maxcpus=1` to the boot parameters ([how to add a boot parameter](https://wiki.ubuntu.com/Kernel/KernelBootParameters)).

In addition, you might want to stop any other actively-running software on the tested machine. We never encountered issues with it, but it might be useful.

## Installation

### 1. Get the x86-64 ISA description:

```bash
cd src/x86/isa_spec
./get_spec.py --extensions BASE SSE SSE2 CLFLUSHOPT CLFSH
```

### 2. Install the executor kernel module:

```bash
cd src/x86/executor
make uninstall  # the command will give an error message, but it's ok!
make clean
make
make install
```

### 3. (Optional) Run Tests

```bash
cd src/tests
./runtests.sh
```

If a few (up to 3) "Detection" tests fail, it's fine, you might just have a slightly different microarchitecture. But if other tests fail - something is broken.
