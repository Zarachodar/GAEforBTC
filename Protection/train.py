from __future__ import division
from __future__ import print_function

import argparse
import time

import numpy as np
import scipy.sparse as sp
import torch
from torch import optim

from model import GCNModelVAE, GCNModelAE, Discriminator, GATModelAE, SAE, G2G
from optimizer import loss_function, ae_loss_function
from utils import load_data, mask_test_edges, preprocess_graph, get_roc_score, AttributedGraph

parser = argparse.ArgumentParser()
parser.add_argument('--model', type=str, default='GAT', help="models used")
parser.add_argument('--seed', type=int, default=42, help='Random seed.')
parser.add_argument('--epochs', type=int, default=100, help='Number of epochs to train.')
parser.add_argument('--hidden1', type=int, default=32, help='Number of units in hidden layer 1.')
parser.add_argument('--hidden2', type=int, default=16, help='Number of units in hidden layer 2.')
parser.add_argument('--lr', type=float, default=0.01, help='Initial learning rate.')
parser.add_argument('--dropout', type=float, default=0., help='Dropout rate (1 - keep probability).')
parser.add_argument('--dataset-str', type=str, default='btc', help='type of dataset.')

args = parser.parse_args()


def gae_for(args):
    print("Using {} dataset".format(args.dataset_str))
    adj, features = load_data(args.dataset_str, 0)
    n_nodes, feat_dim = features.shape
    # print(feat_dim)
    # exit(0)

    # Store original adjacency matrix (without diagonal entries) for later
    adj_orig = adj
    adj_orig = adj_orig - sp.dia_matrix((adj_orig.diagonal()[np.newaxis, :], [0]), shape=adj_orig.shape)
    adj_orig.eliminate_zeros()

    adj_train, train_edges, val_edges, val_edges_false, test_edges, test_edges_false = mask_test_edges(adj)
    adj = adj_train

    # Some preprocessing
    adj_norm = preprocess_graph(adj)
    adj_label = adj_train + sp.eye(adj_train.shape[0])
    # adj_label = sparse_to_tuple(adj_label)
    adj_label = torch.FloatTensor(adj_label.toarray())

    pos_weight = float(adj.shape[0] * adj.shape[0] - adj.sum()) / adj.sum()
    norm = adj.shape[0] * adj.shape[0] / float((adj.shape[0] * adj.shape[0] - adj.sum()) * 2)

    if args.model == 'VAE' or args.model == 'AVAE':
        model = GCNModelVAE(feat_dim, args.hidden1, args.hidden2, args.dropout)
        if args.model == 'AVAE':
            D = Discriminator(feat_dim, args.hidden1, n_nodes, args.dropout)
    elif args.model == 'AE' or args.model == 'AAE':
        model = GCNModelAE(feat_dim, args.hidden1, args.hidden2, args.dropout)
        if args.model == 'AAE':
            D = Discriminator(feat_dim, args.hidden1, n_nodes, args.dropout)
    elif args.model == 'GAT':
        model = GATModelAE(feat_dim, args.hidden1, args.hidden2, args.dropout)
    elif args.model == 'SAE': 
        model = SAE(feat_dim, args.hidden1, args.hidden2, args.dropout)
    elif args.model == 'G2G':
        model = G2G(feat_dim, args.hidden1, args.hidden2, args.dropout)
    else:
        print("Undifined Model")
        return
    print("Using Graph {} model".format(args.model))

    optimizer = optim.Adam(model.parameters(), lr=args.lr)
    if args.model == 'AAE' or args.model == 'AVAE':
        optimizerD = optim.Adam(D.parameters(), lr=args.lr)
        bce_loss = torch.nn.BCELoss()

    hidden_emb = None
    for epoch in range(args.epochs):
        t = time.time()
        model.train()
        optimizer.zero_grad()

        if args.model == 'VAE' or args.model == 'AVAE':
            recovered, mu, logvar = model(features, adj_norm)
            loss = loss_function(preds=recovered, labels=adj_label,
                                 mu=mu, logvar=logvar, n_nodes=n_nodes,
                                 norm=norm, pos_weight=pos_weight)
            hidden_emb = mu.data.numpy()

        elif args.model == 'AE' or args.model == 'AAE':
            recovered, z = model(features, adj_norm)
            loss = ae_loss_function(preds=recovered, labels=adj_label, norm=norm, pos_weight=pos_weight)
            hidden_emb = z.data.numpy()

        elif args.model == 'GAT':
            recovered, z = model(features, adj_norm)
            loss = ae_loss_function(preds=recovered, labels=adj_label, norm=norm, pos_weight=pos_weight)
            hidden_emb = z.data.numpy()

        elif args.model == 'SAE' or args.model == 'G2G':
            recovered, z = model(adj_norm)
            loss = ae_loss_function(preds=recovered, labels=adj_label, norm=norm, pos_weight=pos_weight)
            hidden_emb = z.data.numpy()


        loss.backward()
        cur_loss = loss.item()
        optimizer.step()

        if args.model == 'AAE' or args.model == 'AVAE':
            optimizerD.zero_grad()
            real = D(features, adj_norm)
            # print(real)
            if args.model == 'AAE':
                fake, _ = model(features, adj_norm)
            elif args.model == 'AVAE':
                fake, _, _ = model(features, adj_norm)
            fake = D(features, fake)
            # print(fake)

            real_loss = bce_loss(real, torch.full(real.shape, 1))
            fake_loss = bce_loss(fake, torch.full(real.shape, 0))
            d_loss = real_loss + fake_loss

            d_loss.backward()
            optimizerD.step()

            lossD = d_loss.item()

        
        auc_curr, ap_curr = get_roc_score(hidden_emb, adj_orig, val_edges, val_edges_false)

        print("Epoch:", '%04d' % (epoch + 1), "train_loss=", "{:.5f}".format(cur_loss),
              "val_auc=", "{:.5f}".format(auc_curr), "val_ap=", "{:.5f}".format(ap_curr),
              "time=", "{:.5f}".format(time.time() - t)
              )
        if args.model == 'AAE' or args.model == 'AVAE':
            print("\t\tDiscriminator_loss=", "{:.5f}".format(lossD)
                )

    print("Optimization Finished!")

    auc_score, ap_score = get_roc_score(hidden_emb, adj_orig, test_edges, test_edges_false)
    print('Test AUC score: ' + str(auc_score))
    print('Test AP score: ' + str(ap_score))

    model_name = 'model/' + args.model + '_' + args.dataset_str + '.pt'
    torch.save(model.state_dict(), model_name)


if __name__ == '__main__':
    gae_for(args)
