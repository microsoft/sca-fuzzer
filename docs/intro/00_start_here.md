# Getting started

New to Revizor? Or to side-channel testing in general? You came to the right
place: read this material to quickly get up and running.

## Introductory Materials

* [Revizor at a Glance](01_overview.md): Understand what Revizor is, what problems it solves, and see a quick example of violation detection.
* [Installation Guide](02_install.md): Get Revizor installed on your system and verify your setup.
* [Core Concepts](03_primer.md): Learn about contracts, traces, speculation, and other fundamental concepts needed to use Revizor effectively.
* [Tutorial Series](04_tutorials_start.md): Follow a series of hands-on tutorials that walk you through running your first tests, detecting violations, and rump up all the way to root-cause analysis and design of custom campaigns.
* [Glossary](../glossary.md): A quick reference for key terms used throughout the documentation.

## Academic Deep Dives

Interested in the academic research behind Revizor? Check out these papers:

1. Original paper that introduced the concept of Model-based Relation Testing as well as the Revizor tool: "[Revizor: Testing Black-box CPUs against Speculation Contracts](https://www.microsoft.com/en-us/research/publication/revizor-testing-black-box-cpus-against-speculation-contracts/)"
2. Theoretical foundations of leakage contract: "[Hardware-software contracts for secure speculation](https://www.microsoft.com/en-us/research/publication/hardware-software-contracts-for-secure-speculation/)"
3. Accessible summary of the two papers above, in a journal format: "Revizor: Testing Black-box CPUs against Speculation Contracts". In IEEE Micro, 2023.
4. Paper that introduced speculation filtering, observation filtering, and contract-based input generation: "[Hide and Seek with Spectres: Efficient discovery of speculative information leaks with random testing](https://www.microsoft.com/en-us/research/publication/hide-and-seek-with-spectres-efficient-discovery-of-speculative-information-leaks-with-random-testing/)"
5. Paper that introduced exception-based testing (i.e., focus on Meltdown, Foreshadow) into Revizor: "[Speculation at Fault: Modeling and Testing Microarchitectural Leakage of CPU Exceptions.](https://www.usenix.org/conference/usenixsecurity23/presentation/hofmann)"
6. Paper that introduced testing of cross-VM and user-kernel leaks in Revizor, as well as presented TSA attacks on AMD CPUs: "[Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://www.microsoft.com/en-us/research/wp-content/uploads/2025/07/Enter-Exit-SP26.pdf)"

## Need Help?

If you have any questions or need further assistance, please reach out to the Revizor community through our [GitHub repository](https://github.com/microsoft/sca-fuzzer) or via our [Zulip chat](https://rvzr.zulipchat.com/join/yc2rwy4kr4lamdocl6w33l74/).
