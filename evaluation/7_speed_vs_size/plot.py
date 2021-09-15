#!/usr/bin/env python3

import pandas
# from pandas.tools import plotting
import matplotlib.pyplot as plt

data = pandas.read_csv('entropy.csv', sep=',',)
grouped = data.groupby('name')

fig, axv = plt.subplots(1, 1, sharey='all', sharex='all', figsize=(7, 4), dpi=300)

# add a big axes, hide frame
fig.add_subplot(111, frameon=False)


grouped.boxplot(by='Entropy', column=['testcases'])
# data.boxplot(by='entr', column=['duration'], )


# hide tick and tick label of the big axes
plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)

plt.title("")
plt.ylabel('Test Cases')

plt.savefig('figure.png')
