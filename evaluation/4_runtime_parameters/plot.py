#!/usr/bin/env python3

from argparse import ArgumentParser
import matplotlib.pyplot as plt
import csv
import numpy as np

plt.style.use('seaborn-colorblind')


def lineplot2(args):
    fig, axv = plt.subplots(1, 1, sharey='all', sharex='all', figsize=(7, 4), dpi=300)

    # add a big axes, hide frame
    fig.add_subplot(111, frameon=False)
    # hide tick and tick label of the big axes
    plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
    plt.grid(False)

    plt.xlabel('Fuzzing Round')
    plt.ylabel('Coverage')

    # axc.set_title("Test Case Size = 16")

    for path in args.files:
        cov = []
        ids = []
        try:
            with open(path, 'r') as csvfile:
                results = csv.reader(csvfile, delimiter=',')
                for i, row in enumerate(results):
                    if not row:
                        continue
                    ids.append(int(row[0]))
                    cov.append(int(row[1]))
        except IOError:
            pass

        axv.plot(ids, cov, label=f"Coverage")

        # X = np.arange(len(ids))
        # # width = 0.2  # the width of the bars
        # # axv.bar(X - width, vulns, width, label=f"Vulnerabilities")
        # # axv.bar(X, cov, width, label=f"Coverage")
        # # axv.bar(X + width, ecl, width, label=f"Effective Classes")

    fig.legend()
    plt.savefig('plot.png')


if __name__ == '__main__':
    parser = ArgumentParser(description='', add_help=False)
    parser.add_argument(
        "files",
        nargs="+",
    )
    args = parser.parse_args()

    lineplot2(args)
