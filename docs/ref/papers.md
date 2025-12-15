# Research Papers

Revizor is a result of extensive academic research in the field of hardware security and microarchitectural side-channel analysis. Below is a list of key research papers related to Revizor, its underlying concepts, and methodologies:


=== "Main Papers"

    If you use Revizor in your research or work, please consider citing some of the following papers:

    * Original paper that introduced the concept of Model-based Relation Testing as well as the Revizor tool:

        > Oleksii Oleksenko, Christof Fetzer, Boris Köpf, Mark Silberstein. "[Revizor: Testing Black-box CPUs against Speculation Contracts](https://www.microsoft.com/en-us/research/publication/revizor-testing-black-box-cpus-against-speculation-contracts/)" in Proceedings of the 27th ACM International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS), 2022.

    * Theoretical foundations of leakage contract:

        > Marco Guarnieri, Boris Köpf, Jan Reineke, and Pepe Vila. "[Hardware-software contracts for secure speculation](https://www.microsoft.com/en-us/research/publication/hardware-software-contracts-for-secure-speculation/)" in Proceedings of the 2021 IEEE Symposium on Security and Privacy (S&P), 2021.

=== "Extensions to Revizor"

    The following papers present significant extensions and improvements to Revizor:

     * Paper that introduced speculation filtering, observation filtering, and contract-based input generation:

        > Oleksii Oleksenko, Marco Guarnieri, Boris Köpf, and Mark Silberstein. "[Hide and Seek with Spectres: Efficient discovery of speculative information leaks with random testing](https://www.microsoft.com/en-us/research/publication/hide-and-seek-with-spectres-efficient-discovery-of-speculative-information-leaks-with-random-testing/)" in Proceedings of the 2023 IEEE Symposium on Security and Privacy (SP), 2022.

    * Paper that introduced exception-based testing (i.e., focus on Meltdown, Foreshadow) into Revizor:

        > Jana Hofmann, Emanuele Vannacci, Cédric Fournet, Boris Köpf, and Oleksii Oleksenko. "[Speculation at Fault: Modeling and Testing Microarchitectural Leakage of CPU Exceptions.](https://www.usenix.org/conference/usenixsecurity23/presentation/hofmann)" in Proceedings of 32nd USENIX Security Symposium (USENIX Security), 2023.

    * Paper that introduced testing of cross-VM and user-kernel leaks in Revizor, as well as presented TSA attacks on AMD CPUs:

        > Oleksii Oleksenko, Flavien Solt, Cédric Fournet, Jana Hofmann, Boris Köpf, Stavros Volos. "[Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://www.microsoft.com/en-us/research/wp-content/uploads/2025/07/Enter-Exit-SP26.pdf)" in Proceedings of the 2026 IEEE Symposium on Security and Privacy (SP), 2026.

=== "Using Revizor"

    The following papers present case studies and practical applications of (parts of) Revizor:

    * **AMuLet, 2025**: Ported Revizor to test Gem5 models of secure speculation mechanisms

        > Bo Fu, Leo Tenenbaum, David Adler, Assaf Klein, Arpit Gogia, Alaa R. Alameldeen, Marco Guarnieri, Mark Silberstein, Oleksii Oleksenko, and Gururaj Saileshwar. "[AMuLeT: Automated Design-Time Testing of Secure Speculation Countermeasures](https://arxiv.org/pdf/2503.00145)". In Proceedings of the 30th ACM International Conference on Architectural Support for Programming Languages and Operating Systems, Volume 2 (ASPLOS '25). Association for Computing Machinery, New York, NY, USA, 32–47. https://doi.org/10.1145/3676641.3716247

    * **LmTest, 2024**: Used a modified version of Revizor's leakage model to test cryptographic libraries against speculation contracts

        > Gilles Barthe, Marcel Böhme, Sunjay Cauligi, Chitchanok Chuengsatiansup, Daniel Genkin, Marco Guarnieri, David Mateos Romero, Peter Schwabe, David Wu, and Yuval Yarom. 2024. Testing Side-channel Security of Cryptographic Implementations against Future Microarchitectures. In Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security (CCS '24). Association for Computing Machinery, New York, NY, USA, 1076–1090. https://doi.org/10.1145/3658644.3670319



