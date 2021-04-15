#!/usr/bin/env python
# -*- coding:utf-8 -*-


from sklearn import model_selection,preprocessing
from sklearn.naive_bayes import GaussianNB
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import confusion_matrix,classification_report

def plot_confusion_mat(confusion_mat):
    # 注意必须是imshow()
    plt.imshow(confusion_mat,interpolation='nearest',cmap=plt.cm.Paired)
    plt.title('Confusion Matrix')
    plt.colorbar()
    tick_marks=np.arange(4)
    plt.xticks(tick_marks,tick_marks)
    plt.yticks(tick_marks,tick_marks)
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.show()



input_filename='goodx.csv'

X=[]
labels_encoder=[]

with open(input_filename,'r') as f:
    for line in f.readlines():
        data=line[:-1].split(',')
        X.append(data)
X=np.array(X)
# 标记编码

X_encoded=np.empty(X.shape)
# # 处理数值和非数值数据，但是遇到bug...后面需要进行数据清洗！！！
# for i,item in enumerate(X[0]):
#     if(item.isdigit()):
#         print(X[:,i])
#         X_encoded[:,i]=X[:,i]
#     else:
#         labels_encoder.append(preprocessing.LabelEncoder())
#         X_encoded[:,i]=labels_encoder[-1].fit_transform(X[:,i])

for i,item in enumerate(X.shape):
    labels_encoder.append(preprocessing.LabelEncoder())
    X_encoded[:,i]=labels_encoder[-1].fit_transform(X[:,i])
X_encoded=np.array(X_encoded)

x=X_encoded[:,:-1].astype(int)
y=X_encoded[:,-1].astype(int)

# 交叉验证
x_train,x_test,y_train,y_test=model_selection.train_test_split(x,y,test_size=0.2,random_state=7)
model=GaussianNB()
model.fit(x_train,y_train)

# report
y_test_pred=model.predict(x_test)

# 提取性能指标
f1=model_selection.cross_val_score(model,x_test,y_test,scoring='f1_weighted',cv=5)
accu=model_selection.cross_val_score(model,x_test,y_test,scoring='precision_weighted',cv=5)

print("F1 scoring : {}%".format(round(100*f1.mean(),2)))
print("Precision scoring : {}%".format(round(100*accu.mean(),2)))

confusion_mat=confusion_matrix(y_test,y_test_pred)
plot_confusion_mat(confusion_mat)





