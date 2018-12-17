# -*- coding: utf-8 -*-  
import numpy as np  
import scipy as sp  
from sklearn import tree  
from sklearn.metrics import precision_recall_curve  
from sklearn.metrics import classification_report  
from sklearn.cross_validation import train_test_split  
from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
from sklearn.externals import joblib
from sklearn.linear_model import LogisticRegression
import os
from sklearn.externals.six import StringIO  
import pydotplus
#from IPython.display import Image  
 
''''' 数据读入 '''  
data   = []  
labels = []  

with open("/home/myw/DroidBox_4.1.1/train_feature_set.txt",'r') as ifile:
	for line in ifile:  
            tokens =  line.strip().split(',') #type(tokens):list
            data.append([float(tk) for tk in tokens[:-1]])  
	    s = tokens[-1].strip().replace("'",'')  
	    labels.append(s)    
	    
#print data
#print labels
x = np.array(data)  
#print x
labels = np.array(labels)  
#print labels
y = np.zeros(labels.shape)  
#print y
#print apks
ifile.close()
''''' 标签转换为0/1 '''  
y[labels=='malware']=1  
#print y  
#print type(y)

''''' 拆分训练数据与测试数据 '''  
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.0000001,random_state=0)  #随机选取20%:test 80%:train

''''' 使用信息熵作为划分标准，对决策树进行训练 '''  
#lr = tree.DecisionTreeClassifier(criterion='entropy') #0.644   0.823  0/1:0.844  0.807
#lr = RandomForestClassifier(n_estimators = 10)  #0.646
#lr = svm.LinearSVC()#0.678
lr = RandomForestClassifier(n_estimators = 100) #0.902  	0/1:0.899
#lr = svm.NuSVC() #0.684   0.676
#lr = svm.SVC() #0.684  0.6521
#lr = svm.SVC(kernel='linear') #0.664   0.8874
#print(clf) 
#lr = LogisticRegression(C=1e9) #	0.885		0/1:0.854
lr.fit(x_train, y_train)  

''''' 画出决策树''' 
'''
target_names=['benign','malware']
f= open("/home/myw/DroidBox_4.1.1/feature-list.txt","r")
s = f.read()
feature_names = s.strip().split(',')
for i in range(len(feature_names)):
	feature_names[i] = feature_names[i].strip().replace("'",'')
f.close()
#print feature_names,type(feature_names)

dot_data = StringIO() 
#with open("tree.dot", 'w') as dot_data:  
tree.export_graphviz(lr, out_file=dot_data,feature_names=feature_names,class_names=target_names, filled=True, rounded=True,special_characters=True)  
#print dot_data.getvalue()
graph = pydotplus.graph_from_dot_data(dot_data.getvalue()) 
graph.write_pdf("tree-l.pdf")
#Image(graph.create_png())
#os.unlink('tree.dot') delete the file
'''
'''''把模型保存到文件里'''''
os.chdir("/home/myw/DroidBox_4.1.1/model")
joblib.dump(lr, 'lr.model')


