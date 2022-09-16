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

## Submitting Patches and Reporting Issues

To submit a bug or a feature request, use Github [issues](https://github.com/microsoft/sca-fuzzer/issues).

To submit a patch, use the following procedure:
* Fork Revizor on github (https://docs.github.com/en/github/getting-started-with-github/fork-a-repo)
* Create a topic branch (`git checkout -b my_branch`)
* Make sure all tests pass (`./tests/runtests.sh <target_ISA>`) and that the code is formatted accordingly to the [Code Style](#code-style).
* Push to your branch (`git push origin my_branch`)
* Initiate a pull request on github (https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request)
* Wait for the PR to get reviewed and merged

## Code Style

Please follow these coding standards when writing code for inclusion in Revizor.

Python:
* Unless otherwise specified, follow PEP 8. But remember that PEP 8 is only a guide, so respect the style of the surrounding code as a primary goal.
* An exception to PEP 8 is our rules on line lengths. Don’t limit lines of code to 79 characters if it means the code looks significantly uglier or is harder to read. We allow up to 100 characters.
* All files should be formatted using the `flake8` auto-formatter. Use all default settings except for the line width (`--max-line-length 100`)
* The Python and C files use 4 spaces for indentation, and YAML uses 2 spaces.
* The project repository includes an .editorconfig file. We recommend using a text editor with EditorConfig support to avoid indentation and whitespace issues.
* Use underscores, not camelCase, for variable, function and method names (i.e. poll.get_unique_voters(), not poll.getUniqueVoters()).
* Use InitialCaps for class names (or for factory functions that return classes).
* In docstrings, follow PEP 257.

C:
* All files should be formatted using the `clang-format`. The settings are included into the `.clang-format` files in the directories with C files. Just run the formatter with: `clang-format -i *.c`

Misc:
* Remove import statements that are no longer used when you change code. flake8 will identify these imports for you. If an unused import needs to remain for backwards-compatibility, mark the end of with # NOQA to silence the flake8 warning.
* Systematically remove all trailing whitespaces from your code as those add unnecessary bytes, add visual clutter to the patches and can also occasionally cause unnecessary merge conflicts. Some IDE’s can be configured to automatically remove them and most VCS tools can be set to highlight them in diff outputs.
