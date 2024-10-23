# Covert Transaction Graph Detection and Protection

## Introduction

**This** is a framework for Covert Transaction ***Detection*** and ***Protection*** in Blockchain. It can be used to analyze potential covert transactions in Blockchain using relatively little computing including a simple analytics-driven method to extract group-level structural properties from the transaction graph and a blockchain-based covert transmission method using unsupervised graph generation models.

One of them, ***Detection***, is how to use graph structure metrics to distinguish between normal and covert transactions, and contains the normal and covert transaction data we collected from the data sources: https://github.com/1997mint/covert-transaction-model.

Another one, ***Protection*** is how to use graph generative models to protect established covert transactions from being easily detected by graph-structured metrics, including training data and trained model files (model\*.pt).

For a detailed description and experimental results, please take a look at our TIFS paper [Graph-Based Covert Transaction Detection and Protection in Blockchain](https://ieeexplore.ieee.org/document/10375526).

## Citation
If you use this code for your publication, please cite the original paper:
```
@ARTICLE{10375526,
  author={Guo, Zhenyu and Li, Xin and Liu, Jiamou and Zhang, Zijian and Li, Meng and Hu, Jingjing and Zhu, Liehuang},
  journal={IEEE Transactions on Information Forensics and Security}, 
  title={Graph-Based Covert Transaction Detection and Protection in Blockchain}, 
  year={2024},
  volume={19},
  number={},
  pages={2244-2257},
  keywords={Blockchains;Feature extraction;Timing;Protocols;Computer science;Task analysis;Streaming media;Covert communication;covert transaction protection;blockchain;graph generative networks},
  doi={10.1109/TIFS.2023.3347895}}

```

## Contact Info
For help or issues, please submit a GitHub issue.

For personal communication, please contact [Zhenyu Kwok](`zhenyuguo@bit.edu.cn`).
