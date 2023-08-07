import pandas as pd
import csv

d = dict()
with open('ab_degree.csv') as csv_file:
    csv_reader = csv.reader(csv_file,delimiter=',')
    line_count = 0
 
    for row in csv_reader:
        if line_count == 0:
            print(f'Column names are {", ".join(row)}')
            line_count += 1
        else:
            if(d.__contains__(int(row[1]))):
            	d[int(row[1])] += 1
            else:
            	d[int(row[1])] = 1
            line_count += 1
        print(f'Processed {line_count} lines.')
    
print(d)

with open('AB_Counter.csv', 'w', encoding = 'utf-8') as f:
	[f.write('{0},{1}\n'.format(key, value)) for key, value in d.items()]
