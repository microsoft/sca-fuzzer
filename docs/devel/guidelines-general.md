# General Development Guidelines

## Testing

To run automated tests you will need to install a few more dependencies:

* [Bash Automated Testing System](https://bats-core.readthedocs.io/en/latest/index.html)
* [mypy](https://mypy.readthedocs.io/en/latest/getting_started.html#installing-and-running-mypy)
* [flake8](https://flake8.pycqa.org/en/latest/index.html)

With the dependencies installed, you can run the tests with:

```bash
./tests/runtests.sh
```

Note that some of the acceptance tests are microarchitecture-dependent.
These tests are labeled "Detection" (e.g., `"Detection [spectre-type] Spectre V1; load variant"`), and they may fail if the CPU under test does not have a given vulnerability.
Generally, if a few of these tests fail, it is not a problem, but if all of them (or a significant portion) fail, it indicates an issue with the fuzzer.

## Submitting Patches

To submit a patch, use the following procedure:

* Fork Revizor on github:

    [https://docs.github.com/en/github/getting-started-with-github/fork-a-repo](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo)

* Create a topic branch:

```bash
git checkout -b my_branch
```

* Make sure all tests pass (see [Testing](#testing))
* Make sure your code follows the guidelines in [Code Style](guidelines-code-style.md)
* Push to your branch

```bash
git push origin my_branch
```

* Initiate a pull request on github:

    [https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request)

* Wait for the PR to get reviewed and merged

### Contributor License Agreement and Code of Conduct

Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [https://cla.opensource.microsoft.com](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
