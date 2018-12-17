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
import os

os.chdir("/home/myw/DroidBox_4.1.1/model")
clf = joblib.load('lr.model')
''''' 把决策树结构写入文件 ''' 
'''
with open("tree.dot", 'w') as f:  
    f = tree.export_graphviz(clf, out_file=f)  
'''    
''''' 系数反映每个特征的影响力。越大表示该特征在分类中起到的作用越大 '''  
#print(clf.feature_importances_)  

data   = []  
labels = []

with open("/home/myw/DroidBox_4.1.1/test_feature_set.txt",'r') as ifile:
        for line in ifile:  
            tokens = line.strip().split(',') 
            data.append([float(tk) for tk in tokens[:-1]])
	    s = tokens[-1].strip().replace("'",'')  
	    labels.append(s)    

#test_data = [1 0 0 0 0 0 1 1 0 1 0 0 0]
#x = np.array(test_data)

x = np.array(data)  
#print x
labels = np.array(labels)  
#print labels
y = np.zeros(labels.shape)  
y[labels=='malware']=1  
ifile.close()
#print y
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.99999999,random_state=0)
#print x_test
#print y_test

'''''测试结果的打印'''  
answer = clf.predict(x_test) 

#print (answer) #<type 'numpy.ndarray'>
#print y_test
#print "\n"
#print y
'''
for i in range(len(answer)):
    if  answer[i]==1 :
	print str(test_apks[i])+":malware"
    else:
	print str(test_apks[i])+":benign"
    #print u'predict label: %s ' % training_data.target_names[pred]
'''
#if answer == y_test:
#	num  
#print answer == y


print(np.mean( answer == y_test)) #answer==y_train:1.0  
print "accuracy:",clf.score(x_test,y_test)
'''''准确率与召回率'''

#precision, recall, thresholds = precision_recall_curve(y_train, clf.predict(x_train))  
#answer = clf.predict_proba(x)[:,1]  
print classification_report(y_test, answer, target_names = ['benign', 'malware']) 
  
