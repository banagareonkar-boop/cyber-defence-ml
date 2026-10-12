import pandas as pd
data=pd.read_csv("dataset\\KDDTrain+.txt",header=None)
print('data set load succefully')
print(data.head())