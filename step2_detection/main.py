# !/usr/bin/env python
# -*- coding:utf-8 -*-
import urllib
import numpy as np
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB,BernoulliNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC,SVC
import joblib
from sklearn import preprocessing

# 加载数据
def loadFile():
    badXss='./badx.txt'
    goodXss='./goodx.txt'
    bf=[x.strip().lower() for x in open(badXss,'r').readlines()]
    gf=[x.strip().lower() for x in open(goodXss,'r').readlines()]
    return bf,gf

# 特征工程
def MakeFeature(x):
    """
    charList is 关键词特征,markList is 关键符号特征

    :param x:
    :return:featureList
    """
    charList = ["οnmοuseοver=","οnlοad=", "οnerrοr=", "javascript","alert", "src=", "confirm", "onblur"]
    markList = ["=", ":",">", "<", '"', "'", ")","(", "."]
    featureList = []
    for i in x:
        char_count, mark_count = 0, 0
        payload =urllib.parse.unquote(i.lower().strip())
        for charts in charList:
            char_count = payload.count(charts)+ char_count
        for marks in markList:
            mark_count = payload.count(marks) +mark_count
        featureList.append([char_count,mark_count])
    return featureList

# 训练
def train(x,y):
    """
    测试不同方法的训练精度和召回率,方法分别是
    a.多项式先验分布的朴素贝叶斯
    b.伯努利先验分布的朴素贝叶斯
    c.决策树
    d.线性回归
    e.线性支持向量机
    f.高斯核函数的支持向量机

    :param x: train_data
    :param y: train_target
    :return: none
    """
    x_train, x_test, y_train, y_test =train_test_split(x, y, test_size=0.4, random_state=666)
    param = {'n_estimators': 200, 'max_depth':200, 'min_samples_split': 2, 'learning_rate': 0.01}
    NBM = [MultinomialNB(alpha=0.01),
           BernoulliNB(alpha=0.01),
          DecisionTreeClassifier(max_depth=100),
          RandomForestClassifier(criterion='gini', max_depth=100,n_estimators=200),
           LogisticRegression(random_state=40,solver='lbfgs', max_iter=10000, penalty='l2',multi_class='multinomial',class_weight='balanced', C=100),
           LinearSVC(class_weight='balanced',random_state=100, penalty='l2',loss='squared_hinge', C=0.92, dual=False),
           SVC(kernel='rbf', gamma=0.7, C=1),
           # GradientBoostingClassifier(param)  # 梯度提升树
           ]
    NAME = ["多项式", "伯努利", "决策树", "随机森林", "linear regression", "linerSVC", "svc-rbf"]
    for model, modelName in zip(NBM, NAME):
        x_train,y_train=shuffle(x_train,y_train)
        model.fit(x_train, y_train)
        pred = model.predict(x_test)
        dts = len(np.where(pred == y_test))/ len(y_test)
        # recall_rate=np.sum((y_test+pred)==0)/np.sum(y_test==0)
        print("{} 准确率:{:.5f}% ".format(modelName, dts * 100))  #准确率
        # print("{} 召回率:{:.5f}%".format(modelName,recall_rate))  #召回率
        joblib.dump(model, './model.pkl')  # 将模型保存到本地

def predicts(x):
    clf = joblib.load('./model.pkl')  # 加载已保存的模型
    return clf.predict(x)

def run():
    badx, goodx = loadFile()
    goodx = MakeFeature(goodx)
    badx = MakeFeature(badx)
    # goody = [0] * len(goodx)
    # bady = [1] * len(badx)
    goody=np.zeros_like(goodx)
    bady=np.ones_like(badx)
    min_max_scaler = preprocessing.MinMaxScaler()
    X_train_minmax =min_max_scaler.fit_transform(bady)
    x = np.array(goodx + badx).reshape(-1, 2)
    y = np.array(goody + bady).reshape(-1, 1)
    train(x, y)
    testX =["<script>alert(1)</script>", "123123sadas","onloads2s", "scriptsad23asdasczxc","οnlοad=alert(1)"]
    x =MakeFeature(testX)
    for res, req in zip(predicts(x), testX):
        print("XSS==>" if res == 1 else "None==>", req)

if __name__=="__main__":
    run()
