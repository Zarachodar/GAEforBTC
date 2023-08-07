import pickle as pkl
import re
import networkx as nx
import numpy as np
import scipy.sparse as sp
import scipy
import torch
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score

def load_data(dataset, i):
    
    if dataset == 'btc':
        nodes = []
        with open('data/addresslist.txt') as f:
            cnt = 0
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                nodes.append(cnt)
                cnt = cnt + 1
        # print(nodes)
        edges = []
        with open('data/linklist.txt') as f:
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                link = re.findall(r"\d+\d", line)
                link = list(map(int, link))
                link = tuple(link)
                if(len(link) < 2):
                    continue
                edges.append(link)
        # print(edges)
        G = nx.Graph()
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        adj = nx.adjacency_matrix(G)

        features = torch.rand(cnt, 6)
        # print(features)

    elif dataset == 'btc_part':
        nodes = []
        with open('data/node_1.txt') as f:
            cnt = 0
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                nodes.append(int(line))
                cnt = cnt + 1
        # print(nodes)
        edges = []
        with open('data/link_1.txt') as f:
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                link = re.findall(r"\d+\d", line)
                link = list(map(int, link))
                link = tuple(link)
                if(len(link) < 2):
                    continue
                edges.append(link)
        # print(edges)
        G = nx.Graph()
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        adj = nx.adjacency_matrix(G)

        features = torch.rand(cnt, 6)

    elif "abnormal" in dataset:
        nf = 'data/abnormal/node_' + i.__str__() + '.txt'
        lf = 'data/abnormal/link_' + i.__str__() + '.txt'
        nodes = []
        with open(nf) as f:
            cnt = 0
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                nodes.append(int(line))
                cnt = cnt + 1
        # print(nodes)
        edges = []
        with open(lf) as f:
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                link = re.findall(r"\d+\d", line)
                link = list(map(int, link))
                link = tuple(link)
                if(len(link) < 2):
                    continue
                edges.append(link)
        # print(edges)
        G = nx.Graph()
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        adj = nx.adjacency_matrix(G)

        features = torch.rand(cnt, 6)

    elif dataset == 'abnormal_test':
        nodes = []
        with open('data/abnode_1.txt') as f:
            cnt = 0
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                nodes.append(int(line))
                cnt = cnt + 1
        # print(nodes)
        edges = []
        with open('data/ablink_1.txt') as f:
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                link = re.findall(r"\d+\d", line)
                link = list(map(int, link))
                link = tuple(link)
                if(len(link) < 2):
                    continue
                edges.append(link)
        # print(edges)
        G = nx.Graph()
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        adj = nx.adjacency_matrix(G)

        features = torch.rand(cnt, 6)

    elif dataset == 'tree':
        nodes = []
        with open('data/ip_seq.txt') as f:
            cnt = 0
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                nodes.append(cnt)
                cnt = cnt + 1
        # print(nodes)
        edges = []
        with open('data/treelink.txt') as f:
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                link = re.findall(r"\d+\d", line)
                link = list(map(int, link))
                link = tuple(link)
                if(len(link) < 2):
                    continue
                edges.append(link)
        # print(edges)
        G = nx.Graph()
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        adj = nx.adjacency_matrix(G)

        features = torch.rand(cnt, 6)
        # print(features)

    else:
        # load the data: x, tx, allx, graph
        names = ['x', 'tx', 'allx', 'graph']
        objects = []
        for i in range(len(names)):
            '''
            fix Pickle incompatibility of numpy arrays between Python 2 and 3
            https://stackoverflow.com/questions/11305790/pickle-incompatibility-of-numpy-arrays-between-python-2-and-3
            '''
            with open("data/ind.{}.{}".format(dataset, names[i]), 'rb') as rf:
                u = pkl._Unpickler(rf)
                u.encoding = 'latin1'
                cur_data = u.load()
                objects.append(cur_data)
            # objects.append(
            #     pkl.load(open("data/ind.{}.{}".format(dataset, names[i]), 'rb')))
        x, tx, allx, graph = tuple(objects)
        test_idx_reorder = parse_index_file(
            "data/ind.{}.test.index".format(dataset))
        test_idx_range = np.sort(test_idx_reorder)

        # print(graph)

        if dataset == 'citeseer':
            # Fix citeseer dataset (there are some isolated nodes in the graph)
            # Find isolated nodes, add them as zero-vecs into the right position
            test_idx_range_full = range(
                min(test_idx_reorder), max(test_idx_reorder) + 1)
            tx_extended = sp.lil_matrix((len(test_idx_range_full), x.shape[1]))
            tx_extended[test_idx_range - min(test_idx_range), :] = tx
            tx = tx_extended

        features = sp.vstack((allx, tx)).tolil()
        features[test_idx_reorder, :] = features[test_idx_range, :]
        features = torch.FloatTensor(np.array(features.todense()))
        adj = nx.adjacency_matrix(nx.from_dict_of_lists(graph))

    return adj, features


def parse_index_file(filename):
    index = []
    for line in open(filename):
        index.append(int(line.strip()))
    return index


def sparse_to_tuple(sparse_mx):
    if not sp.isspmatrix_coo(sparse_mx):
        sparse_mx = sparse_mx.tocoo()
    coords = np.vstack((sparse_mx.row, sparse_mx.col)).transpose()
    values = sparse_mx.data
    shape = sparse_mx.shape
    return coords, values, shape


def mask_test_edges(adj):
    # Function to build test set with 10% positive links
    # NOTE: Splits are randomized and results might slightly deviate from reported numbers in the paper.
    # TODO: Clean up.

    # Remove diagonal elements
    adj = adj - sp.dia_matrix((adj.diagonal()[np.newaxis, :], [0]), shape=adj.shape)
    adj.eliminate_zeros()
    # Check that diag is zero:
    assert np.diag(adj.todense()).sum() == 0

    adj_triu = sp.triu(adj)
    adj_tuple = sparse_to_tuple(adj_triu)
    edges = adj_tuple[0]
    edges_all = sparse_to_tuple(adj)[0]
    num_test = int(np.floor(edges.shape[0] / 10.))
    num_val = int(np.floor(edges.shape[0] / 20.))

    all_edge_idx = list(range(edges.shape[0]))
    np.random.shuffle(all_edge_idx)
    val_edge_idx = all_edge_idx[:num_val]
    test_edge_idx = all_edge_idx[num_val:(num_val + num_test)]
    test_edges = edges[test_edge_idx]
    val_edges = edges[val_edge_idx]
    train_edges = np.delete(edges, np.hstack([test_edge_idx, val_edge_idx]), axis=0)

    def ismember(a, b, tol=5):
        rows_close = np.all(np.round(a - b[:, None], tol) == 0, axis=-1)
        return np.any(rows_close)

    test_edges_false = []
    while len(test_edges_false) < len(test_edges):
        idx_i = np.random.randint(0, adj.shape[0])
        idx_j = np.random.randint(0, adj.shape[0])
        if idx_i == idx_j:
            continue
        if ismember([idx_i, idx_j], edges_all):
            continue
        if test_edges_false:
            if ismember([idx_j, idx_i], np.array(test_edges_false)):
                continue
            if ismember([idx_i, idx_j], np.array(test_edges_false)):
                continue
        test_edges_false.append([idx_i, idx_j])

    val_edges_false = []
    while len(val_edges_false) < len(val_edges):
        idx_i = np.random.randint(0, adj.shape[0])
        idx_j = np.random.randint(0, adj.shape[0])
        if idx_i == idx_j:
            continue
        if ismember([idx_i, idx_j], train_edges):
            continue
        if ismember([idx_j, idx_i], train_edges):
            continue
        if ismember([idx_i, idx_j], val_edges):
            continue
        if ismember([idx_j, idx_i], val_edges):
            continue
        if val_edges_false:
            if ismember([idx_j, idx_i], np.array(val_edges_false)):
                continue
            if ismember([idx_i, idx_j], np.array(val_edges_false)):
                continue
        val_edges_false.append([idx_i, idx_j])

    assert ~ismember(test_edges_false, edges_all)
    assert ~ismember(val_edges_false, edges_all)
    assert ~ismember(val_edges, train_edges)
    assert ~ismember(test_edges, train_edges)
    assert ~ismember(val_edges, test_edges)

    data = np.ones(train_edges.shape[0])

    # Re-build adj matrix
    adj_train = sp.csr_matrix((data, (train_edges[:, 0], train_edges[:, 1])), shape=adj.shape)
    adj_train = adj_train + adj_train.T

    # NOTE: these edge lists only contain single direction of edge!
    return adj_train, train_edges, val_edges, val_edges_false, test_edges, test_edges_false


def preprocess_graph(adj):
    adj = sp.coo_matrix(adj)
    adj_ = adj + sp.eye(adj.shape[0])
    rowsum = np.array(adj_.sum(1))
    degree_mat_inv_sqrt = sp.diags(np.power(rowsum, -0.5).flatten())
    adj_normalized = adj_.dot(degree_mat_inv_sqrt).transpose().dot(degree_mat_inv_sqrt).tocoo()
    # return sparse_to_tuple(adj_normalized)
    return sparse_mx_to_torch_sparse_tensor(adj_normalized)


def sparse_mx_to_torch_sparse_tensor(sparse_mx):
    """Convert a scipy sparse matrix to a torch sparse tensor."""
    sparse_mx = sparse_mx.tocoo().astype(np.float32)
    indices = torch.from_numpy(
        np.vstack((sparse_mx.row, sparse_mx.col)).astype(np.int64))
    values = torch.from_numpy(sparse_mx.data)
    shape = torch.Size(sparse_mx.shape)
    return torch.sparse.FloatTensor(indices, values, shape)


def get_roc_score(emb, adj_orig, edges_pos, edges_neg):
    def sigmoid(x):
        return 1 / (1 + np.exp(-x))

    # Predict on test set of edges
    adj_rec = np.dot(emb, emb.T)
    preds = []
    pos = []
    for e in edges_pos:
        preds.append(sigmoid(adj_rec[e[0], e[1]]))
        pos.append(adj_orig[e[0], e[1]])

    preds_neg = []
    neg = []
    for e in edges_neg:
        preds_neg.append(sigmoid(adj_rec[e[0], e[1]]))
        neg.append(adj_orig[e[0], e[1]])

    preds_all = np.hstack([preds, preds_neg])
    labels_all = np.hstack([np.ones(len(preds)), np.zeros(len(preds_neg))])
    roc_score = roc_auc_score(labels_all, preds_all)
    ap_score = average_precision_score(labels_all, preds_all)

    return roc_score, ap_score

class AttributedGraph:
    def __init__(self, A, X, z = 1, K = 3):
        self.A = A
        self.X = X
        self.z = z
        self.level_sets = level_sets(A, K)

        # Precompute the cardinality of each level set for every node
        self.level_counts = {
            node: np.array(list(map(len, level_sets)))
            for node, level_sets in self.level_sets.items()
        }

        # Precompute the weights of each node's expected value in the loss
        N = self.level_counts
        self.loss_weights = 0.5 * np.array(
            [N[i][1:].sum() ** 2 - (N[i][1:] ** 2).sum() for i in self.nodes()]
        )

        n = self.A.shape[0]
        self.neighborhoods = [None] * n
        for i in range(n):
            ls = self.level_sets[i]
            if len(ls) >= 3:
                self.neighborhoods[i] = CompleteKPartiteGraph(ls[1:])

    def nodes(self):
        return range(self.A.shape[0])

    def eligible_nodes(self):
        """Nodes that can be used to compute the loss"""
        N = self.level_counts

        # If a node only has first-degree neighbors, the loss is undefined
        return [i for i in self.nodes() if len(N[i]) >= 3]

    def sample_two_neighbors(self, node, size=1):
        """Sample to nodes from the neighborhood of different rank"""

        level_sets = self.level_sets[node]
        if len(level_sets) < 3:
            raise Exception('!')

        return self.neighborhoods[node].sample_edges(size)

def level_sets(A, K):
    """Enumerate the level sets for each node's neighborhood

    Parameters
    ----------
    A : np.array
        Adjacency matrix
    K : int?
        Maximum path length to consider

        All nodes that are further apart go into the last level set.

    Returns
    -------
    { node: [i -> i-hop neighborhood] }
    """

    if A.shape[0] == 0 or A.shape[1] == 0:
        return {}

    # Compute the shortest path length between any two nodes
    D = scipy.sparse.csgraph.shortest_path(
        A.to_dense(), method="D", unweighted=True, directed=False
    )

    # Cast to int so that the distances can be used as indices
    #
    # D has inf for any pair of nodes from different cmponents and np.isfinite
    # is really slow on individual numbers so we call it only once here
    D[np.logical_not(np.isfinite(D))] = -1.0
    D = D.astype(np.int)

    # Handle nodes farther than K as if they were unreachable
    if K is not None:
        D[D > K] = -1

    # Read the level sets off the distance matrix
    set_counts = D.max(axis=1)
    sets = {i: [[] for _ in range(1 + set_counts[i] + 1)] for i in range(D.shape[0])}
    for i in range(D.shape[0]):
        sets[i][0].append(i)

        for j in range(i):
            d = D[i, j]

            # If a node is unreachable, add it to the outermost level set. This
            # trick ensures that nodes from different connected components get
            # pushed apart and is essential to get good performance.
            if d < 0:
                sets[i][-1].append(j)
                sets[j][-1].append(i)
            else:
                sets[i][d].append(j)
                sets[j][d].append(i)

    return sets

class CompleteKPartiteGraph:
    """A complete k-partite graph
    """

    def __init__(self, partitions):
        """
        Parameters
        ----------
        partitions : [[int]]
            List of node partitions where each partition is list of node IDs
        """

        self.partitions = partitions
        self.counts = np.array([len(p) for p in partitions])
        self.total = self.counts.sum()

        assert len(self.partitions) >= 2
        assert np.all(self.counts > 0)

        # Enumerate all nodes so that we can easily look them up with an index
        # from 1..total
        self.nodes = np.array([node for partition in partitions for node in partition])

        # Precompute the partition count of each node
        self.n_i = np.array(
            [n for partition, n in zip(self.partitions, self.counts) for _ in partition]
        )

        # Precompute the start of each node's partition in self.nodes
        self.start_i = np.array(
            [
                end - n
                for partition, n, end in zip(
                    self.partitions, self.counts, self.counts.cumsum()
                )
                for node in partition
            ]
        )

        # Each node has edges to every other node except the ones in its own
        # level set
        self.out_degrees = np.full(self.total, self.total) - self.n_i

        # Sample the first nodes proportionally to their out-degree
        self.p = self.out_degrees / self.out_degrees.sum()

    def sample_edges(self, size=1):
        """Sample edges (j, k) from this graph uniformly and independently

        Returns
        -------
        ([j], [k])
        j will always be in a lower partition than k
        """

        # Sample the originating nodes for each edge
        j = np.random.choice(self.total, size=size, p=self.p, replace=True)

        # For each j sample one outgoing edge uniformly
        #
        # Se we want to sample from 1..n \ start[j]...(start[j] + count[j]). We
        # do this by sampling from 1..#degrees[j] and if we hit a node

        k = np.random.randint(self.out_degrees[j])
        filter = k >= self.start_i[j]
        k += filter.astype(np.int) * self.n_i[j]

        # Swap nodes such that the partition index of j is less than that of k
        # for each edge
        wrong_order = k < j
        tmp = k[wrong_order]
        k[wrong_order] = j[wrong_order]
        j[wrong_order] = tmp

        # Translate node indices back into user configured node IDs
        j = self.nodes[j]
        k = self.nodes[k]

        return j, k