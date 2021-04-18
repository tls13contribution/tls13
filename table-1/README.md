# Security

## Objective
The scripts in this directory aim to analyze the TLS version information of the TLS connections and to see how the TLS versions of the connections per domain vary during our observation period.

## Dataset
You can access the daily connection logs from https://virginia.box.com/s/87fvynxfuz5zqxwnaxd4mqnm9hiq0obu

## Directory Assumption
The directories that contain logs should be structured as follows:

\<root\>/\<date\>/\<000-999\>/\<log files\> (e.g., tls-connections/2020-10-01/375/375890.log)

## How to Use
Run the `count_total_period.py` on the root of the log directories and then `version.py` on the same directory
