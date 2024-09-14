
This repository contains supplementary materials related to the "*Unveiling IoT Malware Secrets: Tracing Attack Flows via Static Taint Analysis*" paper. The materials are currently organized into two main directories: `Datasets` and `Payloads`.

## Datasets

The `Datasets` directory contains datasets used for different research questions (RQs) in our research:

- **`Dataset_CLF_xx.txt`**: This dataset is used for RQ1. Each line in the file follows the format:
```
{md5} {family} {the number of attack functions identified by MTAINT}
```

- **`Dataset_LSA.txt`**: This dataset is used for RQ3. Each line in the file follows the format:
```
{md5} {year} {the number of attack functions identified by MTAINT}
```
  

## Payloads

The `Payloads` directory contains 126 payloads that were either collected from publicly available online sources or extracted from real-world IoT malware samples. These payloads have been used by IoT malware for attacks. We have categorized them into two groups:

- **Content Related (82)**: These payloads were directly extracted from samples. During text matching, specific strings, such as IP addresses and folder names, should be ignored to to ensure better generalization in matching process.

- **Function Name Related (44)**: These payloads can be directly matched if the function name is known.
