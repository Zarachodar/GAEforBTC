import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import networkx as nx
import re
import scipy.stats

def recaccuracy():
    with plt.style.context(['ieee', 'grid']):
        # x = [0.01, 0.025, 0.05, 0.075, 0.1]

        # p1 = [1, 1, 1, 0.857143, 0.857143]
        # r1 = [0.75, 0.916666667,1, 1, 1]
        # f1 = [0.857142857, 0.956521739, 1, 0.923076923, 0.923076923]

        # p1 = [1, 1, 1, 1, 0.923076923]
        # r1 = [0.916666667,1, 1, 1, 1]
        # f1 = [0.956521739, 1, 1, 1, 0.96]

        # p1 = [1, 1, 1, 1, 1]
        # r1 = [0.916666667,1, 1, 1, 1]
        # f1 = [0.956521739, 1, 1, 1, 1]

        # p1 = [1, 1, 1, 1, 0.48]
        # r1 = [0.916666667,1, 1, 1, 1]
        # f1 = [0.956521739, 1, 1, 1, 0.648648649]

        # plt.yticks([i * 0.05 for i in range(6, 30)])

        # plt.plot(x, p1, label = 'Precision')
        # plt.plot(x, r1, label = 'Recall')
        # plt.plot(x, f1, label = 'F1-score')

        # plt.xlabel('ε', fontdict={'fontsize': 10})


        # plt.autoscale(tight = True)
        # plt.legend(edgecolor = 'k')

        x = [3, 10, 15]

        p1 = [0.931964, 0.931964, 0.931964]

        r1 = []
        r2 = [0.16, 0.16666667, 0.125]

        plt.plot(x, p1, label = 'Bare')
        plt.plot(x, r2, label = 'Protected by VGAE')

        plt.xlabel('Th', fontdict={'fontsize': 10})
        plt.legend(edgecolor = 'k')

        plt.show()
        plt.savefig('aftervaebtcpart.pdf', bbox_inches = 'tight')

def JS(p, q):
	M = (p + q) / 2
	return 0.5 * scipy.stats.entropy(p, M, base = 2) + 0.5 * scipy.stats.entropy(q, M, base = 2)

def recdistribution():
    nodes = []
    with open('ab_node_1.txt') as f:
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
    with open('ab_link_1.txt') as f:
        cnt = 0
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

    degree = nx.degree_histogram(G)
    degree = degree[1: ]
    x = range(len(degree))
    y = [z / float(sum(degree)) for z in degree]

    print(y)

    px = np.polyfit(x, y, 2)
    py = np.polyval(px, x)

    edges = []
    with open('ab_reclink_1.txt') as f:
        cnt = 0
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

    G = nx.Graph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)
    degree = nx.degree_histogram(G)
    degree = degree[1: ]
    rx = range(len(degree))
    ry = [z / float(sum(degree)) for z in degree]

    print(ry)

    rpx = np.polyfit(rx, ry, 2)
    rpy = np.polyval(rpx, rx)

    nodes = []
    with open('node_22.txt') as f:
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
    with open('link_22.txt') as f:
        cnt = 0
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

    degree = nx.degree_histogram(G)
    degree = degree[1: ]
    nnx = range(len(degree))
    nny = [z / float(sum(degree)) for z in degree]

    print(nny)

    nnpx = np.polyfit(nnx, nny, 2)
    nnpy = np.polyval(nnpx, nnx)

    # plt.plot(x, y, label = 'Bare covert transaction', linestyle = ':')
    # x = np.arange(0, len(x), 1)
    # py = np.polyval(px, x)
    # rpy = np.polyval(rpx, x)
    # nnpy = np.polyval(nnpx, x)
    # plt.scatter(x, y, s = 1, color = (1, 0, 0))
    print(nnpy)
    JS_y_ry = JS(py[0:3], rpy[0:3])
    JS_y_nny = JS(py[0:3], nnpy[0:3])
    JS_ry_nny = JS(rpy[0:3], nnpy[0:3])
    print(JS_y_ry, JS_y_nny, JS_ry_nny)
    
    # plt.plot(x, rpy, label = 'Protected covert transaction', linestyle = '--')
    # plt.plot(x, nnpy, label = 'Normal transaction')
    # plt.legend(loc = 0)
    # plt.xlabel('Degree')
    # plt.ylabel('Percent')
    # plt.xticks([])
    # plt.yticks([])
    # plt.show()

    # plt.savefig('casestudy.pdf', bbox_inches = 'tight')

recdistribution()