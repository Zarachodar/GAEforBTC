# Graph-based Covert Transaction Detection and Protection in Blockchain

## Introduction

**This** is a framework for Covert Transaction ***Detection*** and ***Protection*** in Blockchain. It can be used to analyze potential covert transactions in Blockchain using relatively little computing including a simple analytics-driven method to extract group-level structural properties from the transaction graph and a blockchain-based covert transmission method using unsupervised graph generation models.

* ***Detection***, is how to use graph structure metrics to distinguish between normal and covert transactions. When multiple covert transactions appear continuously, they often expose the correlation features different from normal transactions. Therefore, we propose graph-based covert transaction detection with structure measurements. Specifically, we first build a transaction graph according to all the transaction information monitored in a period, then try to recognize these features from the graph structure and detect the related covert transactions, including the typical structural measures in the directed graph: the in-degree of nodes, the out-degree of nodes, and the longest path length.

* ***Protection*** is how to use graph generative models to protect established covert transactions from being easily detected by graph-structured metrics. To protect group covert transactions in terms of graph structure features more comprehensive, it is necessary to make covert transactions have the same or similar graph distribution features as normal transactions. Therefore, we propose a method that learns the features of normal transactions and imitates its structural distribution to provide a reference method for the planned covert transactions rather than analyzing the feature differences between normal transactions and covert transactions.

including training data and trained model files (model\*.pt).

For a detailed description and experimental results, please take a look at our TIFS paper [Graph-Based Covert Transaction Detection and Protection in Blockchain](https://ieeexplore.ieee.org/document/10375526).

## DataSet
- For the Normal dataset, in  
    Detection/data/btc_normal_short.json
- For the Covert dataset, in
    Detection/data/abnormal.json
- For details about the dataset, in 
    [covert-transaction-model](https://github.com/1997mint/covert-transaction-model)
    
## Require
- Python 3.11.3

### Packages
- PyTorch (1.0.0)
- scikit-learn (1.5.2)
- pandas (2.0.3)
- numpy (1.25.2)
- matplotlib (3.7.2)
- networkx (3.1)
- scipy (1.11.1)

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

For personal communication, please contact [Zhenyu Kwok] (`zhenyuguo@bit.edu.cn`).
