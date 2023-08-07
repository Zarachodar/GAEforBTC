import torch
import torch.nn as nn
import torch.nn.functional as F

from layers import GraphConvolution
from collections import OrderedDict
from sklearn.cluster import KMeans

class InnerProductDecoder(nn.Module):
    """Decoder for using inner product for prediction."""

    def __init__(self, dropout, act=torch.sigmoid):
        super(InnerProductDecoder, self).__init__()
        self.dropout = dropout
        self.act = act

    def forward(self, z):
        z = F.dropout(z, self.dropout, training=self.training)
        adj = self.act(torch.mm(z, z.t()))
        return adj

class GCNModelAE(nn.Module):
    def __init__(self, input_feat_dim, hidden_dim1, hidden_dim2, dropout):
        super(GCNModelAE, self).__init__()
        self.gc1 = GraphConvolution(input_feat_dim, hidden_dim1, dropout, act=F.relu)
        self.gc2 = GraphConvolution(hidden_dim1, hidden_dim2, dropout, act=lambda x: x)
        self.dc = InnerProductDecoder(dropout, act=lambda x: x)

    def encode(self, x, adj):
        hidden1 = self.gc1(x, adj)
        return self.gc2(hidden1, adj)

    def forward(self, x, adj):
        z = self.encode(x, adj)
        return self.dc(z), z

class GCNModelVAE(nn.Module):
    def __init__(self, input_feat_dim, hidden_dim1, hidden_dim2, dropout):
        super(GCNModelVAE, self).__init__()
        self.gc1 = GraphConvolution(input_feat_dim, hidden_dim1, dropout, act=F.relu)
        self.gc2 = GraphConvolution(hidden_dim1, hidden_dim2, dropout, act=lambda x: x)
        self.gc3 = GraphConvolution(hidden_dim1, hidden_dim2, dropout, act=lambda x: x)
        self.dc = InnerProductDecoder(dropout, act=lambda x: x)

    def encode(self, x, adj):
        hidden1 = self.gc1(x, adj)
        return self.gc2(hidden1, adj), self.gc3(hidden1, adj)

    def reparameterize(self, mu, logvar):
        if self.training:
            std = torch.exp(logvar)
            eps = torch.randn_like(std)
            return eps.mul(std).add_(mu)
        else:
            return mu

    def forward(self, x, adj):
        mu, logvar = self.encode(x, adj)
        z = self.reparameterize(mu, logvar)
        return self.dc(z), mu, logvar

class Discriminator(nn.Module):
    def __init__(self, input_feat_dim, hidden_dim1, n_nodes, dropout):
        super(Discriminator, self).__init__()
        self.gc1 = GraphConvolution(input_feat_dim, hidden_dim1, dropout, act=F.relu)
        self.gc2 = GraphConvolution(hidden_dim1, 1, dropout, act=lambda x: x)
        # self.l1 = nn.Linear(n_nodes, n_nodes)
        # self.relu = nn.ReLU(n_nodes)
        # self.l2 = nn.Linear(n_nodes, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x, adj):
    	z = self.gc2(self.gc1(x, adj), adj)
    	z = z.t()
    	# out = self.l2(self.relu(self.l1(z))).squeeze(0)
    	return self.sigmoid(z).squeeze(0)


# class AdversarialGAE(nn.Module):
#     def __init__(self, input_feat_dim, hidden_dim1, hidden_dim2, dropout):
#         super(AdversarialGAE, self).__init__()
#         self.generator = GCNModelAE(input_feat_dim, hidden_dim1, hidden_dim2, dropout)
#         self.discriminator = Discriminator(input_feat_dim, hidden_dim1, hidden_dim2, dropout)


class GraphAttentionLayer(nn.Module):

    def __init__(self, in_features, out_features, dropout, alpha = 0.01, concat=True):
        super(GraphAttentionLayer, self).__init__()
        self.dropout = dropout
        self.in_features = in_features
        self.out_features = out_features
        self.alpha = alpha
        self.concat = concat

        self.W = nn.Parameter(torch.zeros(size=(in_features, out_features)))
        nn.init.xavier_uniform_(self.W.data, gain=1.414)
        self.a = nn.Parameter(torch.zeros(size=(2*out_features, 1)))
        nn.init.xavier_uniform_(self.a.data, gain=1.414)

        self.leakyrelu = nn.LeakyReLU(self.alpha)

    def forward(self, input, adj):
        adj = adj.to_dense()
        h = torch.mm(input, self.W) # shape [N, out_features]
        N = h.size()[0]

        a_input = torch.cat([h.repeat(1, N).view(N * N, -1), h.repeat(N, 1)], dim=1).view(N, -1, 2 * self.out_features) # shape[N, N, 2*out_features]
        e = self.leakyrelu(torch.matmul(a_input, self.a).squeeze(2))  # [N,N,1] -> [N,N]

        zero_vec = -9e15*torch.ones_like(e)
        attention = torch.where(adj > 0, e, zero_vec)
        attention = F.softmax(attention, dim=1)
        attention = F.dropout(attention, self.dropout, training=self.training)
        h_prime = torch.matmul(attention, h)  # [N,N], [N, out_features] --> [N, out_features]

        if self.concat:
            return F.elu(h_prime)
        else:
            return h_prime

class GATModelAE(nn.Module):
    def __init__(self, input_feat_dim, hidden_dim1, hidden_dim2, dropout):
        super(GATModelAE, self).__init__()
        self.gc1 = GraphAttentionLayer(input_feat_dim, hidden_dim1, dropout)
        self.gc2 = GraphAttentionLayer(hidden_dim1, hidden_dim2, dropout)
        self.dc = InnerProductDecoder(dropout, act=lambda x: x)

    def encode(self, x, adj):
        hidden1 = self.gc1(x, adj)
        return self.gc2(hidden1, adj)

    def forward(self, x, adj):
        z = self.encode(x, adj)
        return self.dc(z), z


class SAE(nn.Module):
    def __init__(self, indim, outdim, dropout, clusters=2):
        super(SAE, self).__init__()

        self.layers = nn.Sequential(OrderedDict({
            'lin1': nn.Linear(indim, 128),
            'sig1': nn.Sigmoid(),
            'lin2': nn.Linear(128, 64),
            'sig2': nn.Sigmoid(),
            'lin3': nn.Linear(64, 128),
            'sig3': nn.Sigmoid(),
            'lin4': nn.Linear(128, outdim),
            'sig4': nn.Sigmoid(),
            }))
        self.clusters = clusters

        self.outputs = {}

        self.layers[0].register_forward_hook(self.get_activation('lin1'))
        self.layers[2].register_forward_hook(self.get_activation('lin2'))
        self.layers[4].register_forward_hook(self.get_activation('lin3'))

        self.dc = InnerProductDecoder(dropout, act=lambda x: x)
    
    def get_activation(self, name):
        def hook(module, input, output):
            self.outputs[name] = output
        return hook

    def encoder(self, x):
        output = self.layers(x)
        return output

    def forward(self, adj):
        z = self.encoder(adj)
        return self.dc(z), z

    def layer_activations(self, layername):
        return torch.mean(torch.sigmoid(self.outputs[layername]), dim=0)

    def sparse_result(self, rho, layername):
        rho_hat = self.layer_activations(layername)
        return rho * np.log(rho) - rho * torch.log(rho_hat) + (1 - rho) * np.log(1 - rho) \
                - (1 - rho) * torch.log(1 - rho_hat)

    def kl_div(self, rho):
        first = torch.mean(self.sparse_result(rho, 'lin1'))
        second = torch.mean(self.sparse_result(rho, 'lin2'))
        return first + second

    def get_index_by_name(self, name):
        return list(dict(self.layers.named_children()).keys()).index(name)

    def loss(self, x_hat, x, beta, rho):
        loss = F.mse_loss(x_hat, x) + beta * self.kl_div(rho)
        return loss

    def get_cluster(self):
        kmeans = KMeans(n_clusters=self.clusters).fit(self.outputs['lin2'].detach().cpu().numpy())
        self.centroids = kmeans.cluster_centers_
        return kmeans.labels_

class G2G(nn.Module):
    def __init__(self, input_feat_dim, hidden_dim1, hidden_dim2, dropout):
        """Construct the encoder

        Parameters
        ----------
        D : int
            Dimensionality of the node attributes
        L : int
            Dimensionality of the embedding

        """
        super().__init__()

        def xavier_init(layer):
            nn.init.xavier_normal_(layer.weight)
            # TODO: Initialize bias with xavier but pytorch cannot compute the
            # necessary fan-in for 1-dimensional parameters

        self.linear1 = nn.Linear(input_feat_dim, hidden_dim1)
        self.linear_mu = nn.Linear(hidden_dim1, hidden_dim2)
        self.linear_sigma = nn.Linear(hidden_dim1, hidden_dim2)

        xavier_init(self.linear1)
        xavier_init(self.linear_mu)
        xavier_init(self.linear_sigma)

        self.dc = InnerProductDecoder(dropout, act=lambda x: x)

    def reparameterize(self, mu, logvar):
        if self.training:
            std = torch.exp(logvar)
            eps = torch.randn_like(std)
            return eps.mul(std).add_(mu)
        else:
            return mu

    def forward(self, node):
        h = F.relu(self.linear1(node))
        mu = self.linear_mu(h)
        sigma = F.elu(self.linear_sigma(h)) + 1

        z = self.reparameterize(mu, sigma)

        return self.dc(z), mu, sigma