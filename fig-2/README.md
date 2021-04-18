# Deployment

## Objective
The scripts in this directory aim to analyze the connection logs and to see the number of the connections per particular TLS version on a daily basis.

## Dataset
You can access the daily connection logs from https://virginia.box.com/s/87fvynxfuz5zqxwnaxd4mqnm9hiq0obu

## Directory Assumption
The directories that contain logs should be structured as follows:

<home>/<date>/<000-999>/<log files> (e.g., tls-connections/2020-10-01/375/375890.log)

## How to Use
Run the `count_total_period.py' on the home of the log directories
