import json
import numpy as np
import pandas as pd
import random
import re
import matplotlib.pyplot as plt
import networkx as nx
from networkx.algorithms.dag import dag_longest_path_length

def count():
    normals = set()
    normals_list = list()
    normal_cnt = 0
    with open('btc_normal_short.json') as f:
        while(True):
            line = f.readline()
            if len(line) == 0:
                break
            l = json.loads(line)
            normal_cnt = normal_cnt + 1
            address = l['addresses']
            for elm in address:
                normals.add(elm)
                normals_list.append(elm)

        print('Normal: ' + normal_cnt.__str__())
        print('Related Addresses: ' + len(normals).__str__())
        print('Presented Addresses: ' + len(normals_list).__str__())
        print()

    abnormals = set()
    abnormals_list = list()
    abnormal_cnt = 0
    with open('abnormal.json') as f:
        while(True):
            line = f.readline()
            if len(line) == 0:
                break
            l = json.loads(line)
            abnormal_cnt = abnormal_cnt + 1
            address = l['addresses']
            for elm in address:
                abnormals.add(elm)
                abnormals_list.append(elm)

        print('Abnormal: ' + abnormal_cnt.__str__())
        print('Related Addresses: ' + len(abnormals).__str__())
        print('Presented Addresses: ' + len(abnormals_list).__str__())
        print()

    anomaly = abnormals.difference(normals)
    print('Abnormal Related Only Addresses: ' + len(anomaly).__str__())

    both = normals & abnormals
    print('Related Both Addresses: ' + len(both).__str__())

    print()

    tests = set()
    tests_list = list()
    test_cnt = 0
    with open('test-new data-11.14.json') as f:
        while(True):
            line = f.readline()
            if len(line) == 0:
                break
            l = json.loads(line)
            test_cnt = test_cnt + 1
            address = l['addresses']
            for elm in address:
                tests.add(elm)
                tests_list.append(elm)

        print('Test: ' + test_cnt.__str__())
        print('Related Addresses: ' + len(tests).__str__())
        print('Presented ddresses: ' + len(tests_list).__str__())
        print()

    return len(normals), len(abnormals), len(tests)


def addresslist():
    normal = set()
    normal_cnt = 0
    with open('addresslist.txt', 'w') as fp:
        with open('btc_normal_short.json') as f:
            # fp.write('Id,Address\n')
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                l = json.loads(line)
                address = l['addresses']
                for elm in address:
                    if elm in normal:
                        continue
                    else:
                        normal.add(elm)
                        addressfile = normal_cnt.__str__() + ' ' + elm.__str__() + '\n'
                        print(addressfile)
                        fp.write(addressfile)
                        normal_cnt = normal_cnt + 1

        fp.close()
        print("addresslist.txt Done.")

def linklist():
    with open('linklist.txt', 'w') as fp:
        with open('btc_normal_short.json') as f:
            with open('addresslist.txt', 'r') as fs:
                # fp.write('In,Out\n')
                while(True):
                    line = f.readline()
                    if len(line) == 0:
                        f.close()
                        break
                    l = json.loads(line)
                    address = l['addresses']
                    output_address = l['outputs']['addresses']
                    print(len(output_address))
                    if(output_address is not None):
                        output_address = output_address[0]
                        address.remove(output_address)

                    else:
                        continue    
                        # have no next one

                    for input_address in address:

                        input_cnt = 0
                        output_cnt = 0
                        fs.seek(0)
                        while(True):
                            ls = fs.readline()
                            if len(ls) == 0:
                                break
                            if(ls.find(input_address) != -1):
                                in_cnt = input_cnt
                            if(ls.find(output_address) != -1):
                                out_cnt = output_cnt
                            input_cnt = input_cnt + 1
                            output_cnt = output_cnt + 1

                        link = in_cnt.__str__() + ' ' + out_cnt.__str__() + '\n'
                        input_cnt = 0
                        output_cnt = 0
                        
                        # print(link)

                        fp.write(link)

        fs.close()
        fp.close()
        print("linklist.txt Done.")

def ab_addresslist():
    normal = set()
    normal_cnt = 0
    with open('ab_addresslist.txt', 'w') as fp:
        with open('abnormal.json') as f:
            # fp.write('Id,Address\n')
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                l = json.loads(line)
                address = l['addresses']
                for elm in address:
                    if elm in normal:
                        continue
                    else:
                        normal.add(elm)
                        addressfile = normal_cnt.__str__() + ' ' + elm.__str__() + '\n'
                        print(addressfile)
                        fp.write(addressfile)
                        normal_cnt = normal_cnt + 1

        fp.close()
        print("ab_addresslist.txt Done.")

def ab_linklist():
    with open('ab_linklist.txt', 'w') as fp:
        with open('abnormal.json') as f:
            with open('ab_addresslist.txt', 'r') as fs:
                # fp.write('In,Out\n')
                while(True):
                    line = f.readline()
                    if len(line) == 0:
                        f.close()
                        break
                    l = json.loads(line)
                    address = l['addresses']
                    out_address = []
                    for output in l['outputs']:
                        out_address_temp = output['addresses']
                        # print(len(out_address_temp))
                        if(out_address_temp is not None):
                            out_address.append(out_address_temp[0])
                            address.remove(out_address_temp[0])

                        else:
                            continue    
                            # have no next one

                    for input_address in address:
                        for output_address in out_address:

                            input_cnt = 0
                            output_cnt = 0
                            fs.seek(0)
                            while(True):
                                ls = fs.readline()
                                if len(ls) == 0:
                                    break
                                if(ls.find(input_address) != -1):
                                    in_cnt = input_cnt
                                if(ls.find(output_address) != -1):
                                    out_cnt = output_cnt
                                input_cnt = input_cnt + 1
                                output_cnt = output_cnt + 1

                            link = in_cnt.__str__() + ' ' + out_cnt.__str__() + '\n'
                            input_cnt = 0
                            output_cnt = 0
                            
                            print(link)

                            fp.write(link)

        fs.close()
        fp.close()
        print("ab_linklist.txt Done.")

def new_addresslist():
    normal = set()
    normal_cnt = 0
    with open('o_addresslist.txt', 'w') as fp:
        with open('transactiondate-o.json') as f:
            # fp.write('Id,Address\n')
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                l = json.loads(line)
                address = l['addresses']
                for elm in address:
                    if elm in normal:
                        continue
                    else:
                        normal.add(elm)
                        addressfile = normal_cnt.__str__() + ' ' + elm.__str__() + '\n'
                        print(addressfile)
                        fp.write(addressfile)
                        normal_cnt = normal_cnt + 1

        fp.close()
        print("o_addresslist.txt Done.")

def new_linklist():
    with open('o_linklist.txt', 'w') as fp:
        with open('transactiondate-o.json') as f:
            with open('o_addresslist.txt', 'r') as fs:
                # fp.write('In,Out\n')
                while(True):
                    line = f.readline()
                    if len(line) == 0:
                        f.close()
                        break
                    l = json.loads(line)
                    address = l['addresses']
                    out_address = []
                    for output in l['outputs']:
                        out_address_temp = output['addresses']
                        # print(len(out_address_temp))
                        if(out_address_temp is not None):
                            out_address.append(out_address_temp[0])
                            address.remove(out_address_temp[0])

                        else:
                            continue    
                            # have no next one

                    for input_address in address:
                        for output_address in out_address:

                            input_cnt = 0
                            output_cnt = 0
                            fs.seek(0)
                            while(True):
                                ls = fs.readline()
                                if len(ls) == 0:
                                    break
                                if(ls.find(input_address) != -1):
                                    in_cnt = input_cnt
                                if(ls.find(output_address) != -1):
                                    out_cnt = output_cnt
                                input_cnt = input_cnt + 1
                                output_cnt = output_cnt + 1

                            link = in_cnt.__str__() + ' ' + out_cnt.__str__() + '\n'
                            input_cnt = 0
                            output_cnt = 0
                            
                            print(link)

                            fp.write(link)

        fs.close()
        fp.close()
        print("o_linklist.txt Done.")

def featurelist():
    with open('featurelist.txt', 'w') as fp:
        with open('addresslist.txt') as f:
            cnt_f = 6
            cnt = 0
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                feature = cnt.__str__()
                cnt = cnt + 1

                for i in range(cnt_f):
                    feature = feature + '\t' + round(random.random(), 5).__str__()
                feature = feature + '\tNormal\n'
                print(feature)

                fp.write(feature)

    fp.close()
    print("featurelist.txt Done.")

def adj_matrix():
    n, _, _ = count()
    matrix = np.zeros((n, n))
    with open('btc_normal_short.json') as f:
        with open('addresslist.txt', 'r') as fs:
            while(True):
                line = f.readline()
                if len(line) == 0:
                    f.close()
                    break
                l = json.loads(line)
                input_address = l['inputs']['addresses'][0]
                output_address = l['outputs']['addresses']
                if(output_address is not None):
                    output_address = output_address[0]
                else:
                    continue    
                    # have no next one

                total = l['total']

                cnt = 0
                fs.seek(0)
                while(True):
                    ls = fs.readline()
                    if len(ls) == 0:
                        break
                    if(ls.find(input_address) != -1):
                        input_cnt = cnt
                    if(ls.find(output_address) != -1):
                        output_cnt = cnt
                    cnt = cnt + 1

                matrix[input_cnt][output_cnt] = matrix[input_cnt][output_cnt] + total

        fs.close()

    print(matrix)
    with open('adj_matrix.txt', 'w') as fs:
        for i in range(n):
            adjlist = ''
            for j in range(n):
                if j == n - 1:
                    adjlist = adjlist + matrix[i][j].__str__()
                else:
                    adjlist = adjlist + matrix[i][j].__str__() + '\t'
            print(adjlist)
            fs.write(adjlist)

    fs.close()

    print("adj_matrix.txt Done.")

def filter():
    nodes = []
    with open('o_addresslist.txt') as f:
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
    with open('o_linklist.txt') as f:
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

    adj = nx.adjacency_matrix(G)

    # nx.draw(G, node_size = 10)
    # plt.show()

    # print(G.degree)
    # degree = []
    # cnt = 0
    # for i in range(len(G.degree)):
    #     if(G.degree[i] == 25):
    #         print(i)
    #     degree.append(G.degree[i])
    # print(max(degree))

    newnet = []
    # print(list(nx.connected_components(G)))
    g_cnt = 0
    for i in list(nx.connected_components(G)):
        if len(i) > 4:
            # print(i)
            g_cnt = g_cnt + 1
            g_fn = "abnormal\\o\\node_" + g_cnt.__str__() + ".txt"
            # g_fn = "abnormal_csv\\node_" + g_cnt.__str__() + ".csv"
            with open(g_fn, 'w') as f:
                # f.write("Id,Node\n")
                for j in i:
                    f.write(j.__str__() + "\n")
                    # f.write(j.__str__() + "," + j.__str__() + "\n")
            f.close()


    # print(sum(newnet, []))

def subgraph_link(f):
    f_cnt = f
    nodefile = "abnormal\\o\\node_" + f_cnt.__str__() + ".txt"
    linkfile = "abnormal\\o\\link_" + f_cnt.__str__() + ".txt"
    # linkfile = "abnormal_csv\\link_" + f_cnt.__str__() + ".csv"
    with open(nodefile) as f:
        with open(linkfile, "w") as fs:
            # fs.write('In,Out\n')
            while(True):
                node = f.readline()
                # print(node)
                if(len(node) == 0):
                    break
                with open("o_linklist.txt") as fp:
                     while(True):
                        line = fp.readline()
                        # print(line)
                        if(len(line) == 0):
                            break
                        in_node  = line.split(" ")[0]
                        out_node = line.split(" ")[1]
                        if(node == line or node == out_node):
                            fs.write(line)
                            # fs.write(line.replace(" ", ","))
    fs.close()
    fp.close()
    f.close()

def longestpath(f):
    # if(f == 62):
    #     print(f.__str__() + ": 0")
    #     return f, 0
    f_cnt = f

    nodefile = "abnormal\\o\\node_" + f_cnt.__str__() + ".txt"
    linkfile = "abnormal\\o\\link_" + f_cnt.__str__() + ".txt"

    nodes = []
    with open(nodefile) as f:
        while(True):
            line = f.readline()
            if len(line) == 0:
                f.close()
                break
            nodes.append(int(line))

    print(len(nodes))
    edges = []
    with open(linkfile) as f:
        cnt = 0
        while(True):
            line = f.readline()
            if len(line) == 0:
                f.close()
                break
            link = line.split(" ")
            link = list(map(int, link))
            link = tuple(link)
            # print(link)
            edges.append(link)
    # print(edges)
    G = nx.DiGraph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

    # nx.draw(G)
    # plt.show()
    if(f_cnt == 62):
    	print(f_cnt.__str__() + ": 0")
    	return len(nodes), 0

    # print(f_cnt.__str__() + ": " + dag_longest_path_length(G).__str__())
    # return len(nodes), dag_longest_path_length(G)
    print(f_cnt.__str__() + ": " + dag_longest_path_length(G).__str__())
    return len(nodes), dag_longest_path_length(G)

def varofdegree(f):
    # if(f == 62):
    #     print(f.__str__() + ": 0")
    #     return f, 0
    f_cnt = f

    nodefile = "abnormal\\node_" + f_cnt.__str__() + ".txt"
    linkfile = "abnormal\\link_" + f_cnt.__str__() + ".txt"

    nodes = []
    with open(nodefile) as f:
        while(True):
            line = f.readline()
            if len(line) == 0:
                f.close()
                break
            nodes.append(int(line))

    print(len(nodes))
    edges = []
    with open(linkfile) as f:
        cnt = 0
        while(True):
            line = f.readline()
            if len(line) == 0:
                f.close()
                break
            link = line.split(" ")
            link = list(map(int, link))
            link = tuple(link)
            # print(link)
            edges.append(link)
    # print(edges)
    G = nx.DiGraph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

    # nx.draw(G)
    # plt.show()
    degree = list(dict(G.out_degree()).values())

    print(f_cnt.__str__() + ": " + np.var(degree).__str__())
    return len(nodes), np.var(degree)

def fordegree(f):
    # if(f == 62):
    #     print(f.__str__() + ": 0")
    #     return f, 0
    f_cnt = f

    nodefile = "abnormal\\node_" + f_cnt.__str__() + ".txt"
    linkfile = "abnormal\\link_" + f_cnt.__str__() + ".txt"

    nodes = []
    with open(nodefile) as f:
        while(True):
            line = f.readline()
            if len(line) == 0:
                f.close()
                break
            nodes.append(int(line))

    # print(len(nodes))

    edges = []
    with open(linkfile) as f:
        cnt = 0
        while(True):
            line = f.readline()
            if len(line) == 0:
                f.close()
                break
            link = line.split(" ")
            link = list(map(int, link))
            link = tuple(link)
            # print(link)
            edges.append(link)
    # print(edges)

    G = nx.DiGraph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

    # nx.draw(G)
    # plt.show()
    degree = list(dict(G.degree()).values())

    # print(f_cnt.__str__() + ": " + np.var(degree).__str__())
    return nodes, degree

if __name__ == '__main__':
    count()
    addresslist()
    linklist()
    ab_addresslist()
    ab_linklist()
    new_addresslist()
    new_linklist()
    featurelist()
    adj_matrix()
    filter()
    # for i in range(1, 2):
    #     subgraph_link(i)
    # longestpath(1)
    # node = []
    # lenth = []
    # var = []
    # for i in range(1, 13):
    #     # n, l = longestpath(i)
    #     n, l = varofdegree(i)
    #     node.append(n)
    # #     # lenth.append(l)
    #     var.append(l)
    # dataframe = pd.DataFrame({"nodenum": node, "var of outdegree": var})
    # print(dataframe)
    # dataframe.to_csv("ab_var_of_outdegree.csv")
    # nodelist = []
    # degreelist = []
    # for i in range(1, 13):
    #     n, l = fordegree(i)
    #     print(l)
    #     nodelist = nodelist + n
    #     degreelist = degreelist + l

    # # print(len(nodelist))
    # dataframe = pd.DataFrame({"degree": degreelist})
    # dataframe.to_csv("ab_degree.csv")



