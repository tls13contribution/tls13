# TLS 1.3 in Practice: How TLS 1.3 Contributes to the Internet

## Objective
This repository aims to publicize the dataset and the scripts used in the paper "TLS 1.3 in Practice: How TLS 1.3 Contributes to the Internet (thewebconf 2021)".

## Dataset
You can find all the datasets used in the paper at:

[dataset] (https://virginia.box.com/s/87fvynxfuz5zqxwnaxd4mqnm9hiq0obu)

## Organization
This repository is organized as follows:

 - applications: the directory contains the applications used to collect the data.
 - paper: the directory contains the pdf file of the paper.
 - testbed: the directory contains the source code of the applications in the testbed, which aims to check if a web browser supports the downgrade protection mechanism
 - websites: the directory contains the list of the target websites that we analyzed in our paper.

 - fig-1\_fig-4: the directory contains the scripts implementing Figure 1 and mining the raw data to draw Figure 4
 - fig-2: the directory contains the scripts regarding the TLS 1.3 adoption topic
 - fig-3: the directory contains the csv files that include the platforms and the number of websites that runs on them
 - table-1: the directory contains the scripts used to analyze the transition of the TLS versions per domain
 - table-2\_table-3: the directory contains the csv file of the version transition information per domain
