# How To Make Figure 4

## 1. Extract the TLS 1.3 connections from daily crawled data
- You can get the dataset at https://virginia.box.com/s/87fvynxfuz5zqxwnaxd4mqnm9hiq0obu 
- You can also get the extracted connections in the TLS 1.3 Connections directory of the above storage.

## 2. Run the platform identification script with the following options
- You can run the script by `python3 platform_identification.py --input test_input.csv --output test_output.csv --ratio test_ratio.csv'
- The script will generate two output files. One is a file that contains all the domains with their classification results (first party/third party). The other is a file that contains the daily ratio of the first party to the third party domains.
- You can specify the output file name with the option --output and --ratio.
- The output file is the result of the algorithm detailed in Figure 1 and the ratio file is used to draw Figure 4.
