This demo shows how Revizor can find real-world vulnerabilities in CPUs.
Each config here is intentionally made to detect only one type of vulnerabilities.

For example, if you fuzz an Intel CPU with `conf-v1.yaml`, you will likely detect an instance of Spectre V1.
(of course, there is always a chance that you will find a new previously-unknown vulnerability with this config, but the likelihood is rather low).

This demo targets Intel CPUs. Other microarchitectures are not yet supported (but coming soon!).

* Spectre V1 ([description](https://meltdownattack.com/)):

```
cd src
./cli.py fuzz -s x86/isa_spec/base.json -c ../demo/conf-v1.yaml -i 50 -n 10000
```
Expected duration - several seconds.

* MDS or LVI-Null, depending on the CPU model ([description of MDS](https://mdsattacks.com/) and [LVI](https://lviattack.eu/)):

```
cd src
./cli.py fuzz -s x86/isa_spec/base.json -c ../demo/conf-v1.yaml -i 50 -n 10000
```
Expected duration - several minutes.

* Spectre V4 ([description](https://www.cyberus-technology.de/posts/2018-05-22-intel-store-load-spectre-vulnerability.html)):

```
cd src
./cli.py fuzz -s x86/isa_spec/base.json -c ../demo/conf-v4.yaml -i 50 -n 10000
```
Expected duration - 5-20 minutes.


* Spectre V1-Var ([description](https://dl.acm.org/doi/10.1145/3503222.3507729) and [here](https://eprint.iacr.org/2022/715.pdf))

```
cd src
./cli.py fuzz -s x86/isa_spec/base.json -c ../demo/conf-v1.yaml -i 50 -n 10000
```
Expected duration - several minutes.
