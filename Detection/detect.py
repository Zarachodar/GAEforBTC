import numpy
import csv
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split as ts

f = "var_of_degree.csv"
fl = 0

# af = "ab_dag_longest_path_length.csv"
# afl = 1

x = []
y = []

with open(f, newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        x.append(float(row['var of degree']))
        y.append(fl)
print(len(x))

# with open(af, newline='') as csvfile:
#     reader = csv.DictReader(csvfile)
#     for row in reader:
#         x.append(float(row['len/num']))
#         y.append(afl)

# print(len(x))

ncnt = 0
abcnt = 0
for i in range(len(x)):
	if(abs(25-x[i]) <= 1) and (y[i] == 1):
		abcnt = abcnt + 1
	if(abs(25-x[i]) > 1) and (y[i] == 0):
		ncnt = ncnt + 1

print(ncnt, abcnt)
