# Contributing

As an open source project, Revizor welcomes contributions and suggestions.

## Contributor License Agreement and Code of Conduct

Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Reporting Issues

To submit a bug or a feature request, use Github [issues](https://github.com/microsoft/sca-fuzzer/issues).

If you have a question or need help, please use [Github Discussions](https://github.com/microsoft/sca-fuzzer/discussions) and tag the maintainer (@OleksiiOleksenko) for visibility.

## Submitting Patches

To submit a patch, use the following procedure:
* Fork Revizor on github (https://docs.github.com/en/github/getting-started-with-github/fork-a-repo)
* Create a topic branch (`git checkout -b my_branch`)
* Make sure all tests pass (`./tests/runtests.sh <target_ISA>`) and that the code is formatted accordingly to the [Code Style](docs/development.md).
* Push to your branch (`git push origin my_branch`)
* Initiate a pull request on github (https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request)
* Wait for the PR to get reviewed and merged
