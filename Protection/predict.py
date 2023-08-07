from __future__ import division
from __future__ import print_function

import argparse
import time
import pandas as pd

import numpy as np
import scipy.sparse as sp
import torch
from torch import optim

from model import GCNModelVAE, GCNModelAE, Discriminator
from optimizer import loss_function, ae_loss_function
from utils import load_data, mask_test_edges, preprocess_graph, get_roc_score

parser = argparse.ArgumentParser()
parser.add_argument('--model', type=str, default='AE', help="models used")
parser.add_argument('--datasettype', type=str, default='btc', help='type of training dataset.')
parser.add_argument('--seed', type=int, default=42, help='Random seed.')
parser.add_argument('--hidden1', type=int, default=32, help='Number of units in hidden layer 1.')
parser.add_argument('--hidden2', type=int, default=16, help='Number of units in hidden layer 2.')
parser.add_argument('--dropout', type=float, default=0., help='Dropout rate (1 - keep probability).')
parser.add_argument('--dataset-str', type=str, default='btc', help='type of prediction dataset.')

args = parser.parse_args()

def predict(args, i):

    print("Using {} dataset".format(args.dataset_str + '/' + i.__str__()))
    adj, features = load_data(args.dataset_str, i)
    # print(adj)
    n_nodes, feat_dim = features.shape

    # Store original adjacency matrix (without diagonal entries) for later
    adj_orig = adj
    adj_orig = adj_orig - sp.dia_matrix((adj_orig.diagonal()[np.newaxis, :], [0]), shape=adj_orig.shape)
    adj_orig.eliminate_zeros()

    adj_train, train_edges, val_edges, val_edges_false, test_edges, test_edges_false = mask_test_edges(adj)
    adj = adj_train
    # print(adj_orig.shape[0])

    # Some preprocessing
    adj_norm = preprocess_graph(adj)
 
    if args.model == 'VAE' or args.model == 'AVAE':
        model = GCNModelVAE(feat_dim, args.hidden1, args.hidden2, args.dropout)
        if args.model == 'AVAE':
            D = Discriminator(feat_dim, args.hidden1, n_nodes, args.dropout)
    elif args.model == 'AE' or args.model == 'AAE':
        model = GCNModelAE(feat_dim, args.hidden1, args.hidden2, args.dropout)
        if args.model == 'AAE':
            D = Discriminator(feat_dim, args.hidden1, n_nodes, args.dropout)
    else:
        print("Undifined Model")
        return
    print("Using Graph {} model".format(args.model))

    model_name = "model/" + args.model + '_' + args.datasettype + '.pt'
    m_state_dict = torch.load(model_name)
    model.load_state_dict(m_state_dict)

    if args.model == 'VAE' or args.model == 'AVAE':    
        recovered, _, _ = model(features, adj_norm)

    elif args.model == 'AE' or args.model == 'AAE':
        recovered, _ = model(features, adj_norm)

    # print(adj)
    recovered = recovered.detach().numpy()
    # print(torch.FloatTensor(adj_train.toarray()))
    for i in range(recovered.shape[0]):
        recovered[i][i] = 0
    # print(recovered)

    rec = np.zeros(recovered.shape)

    x = []
    y = []
    for i in range(recovered.shape[0]):
        for j in range(recovered.shape[1]):
            if(recovered[i][j] >= np.max(recovered) / 2):
                rec[i][j] = 1
                x.append(i)
                y.append(j)
    # print(x)

    # i = np.argpartition(recovered.ravel(), -adj_orig.shape[0])[-adj_orig.shape[0]:]
    # i2d = np.unravel_index(i, recovered.shape)
    # # rec = recovered[i2d]

    # # rec = np.zeros(adj.shape)
    # # rec[i2d] = 1
    # print(i2d)
    # return i2d
    degree = []
    for i in range(rec.shape[0]):
        if(np.sum(rec[i]) == 0):
            continue
        degree.append(np.sum(rec[i]))

    print(np.var(degree))

    return np.var(degree)

if __name__ == '__main__':

    var_degree = []
    for i in range(12):
        x = predict(args, i + 1)
        var_degree.append(x)

    print(var_degree)
    # print(x)
    # with open("relink.csv", 'w') as f:
    #     for i in range(len(x)):
    #         line = x[i].__str__() + ',' + y[i].__str__() + '\n'
    #         f.write(line)