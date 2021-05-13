#!/usr/bin/env python
# -*- coding:utf-8 -*-

import numpy as np
# from scapy.main import _validate_local
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB,BernoulliNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC,SVC
import joblib
from sklearn import preprocessing,model_selection
# from sklearn.metrics import confusion_matrix,classification_report
import matplotlib.pyplot as plt
import warnings
import os
from .get_goodx import GetGoodx
from .get_feature import GetFeature
from .get_badx import GetBadx
import pprint
import argparse 

DATASET=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dataset')
GOOD_DATASET_PATH= os.path.join(DATASET,'goodx.csv')
BAD_DATASET_PATH= os.path.join(DATASET, 'badx.csv')
# BAD_PCAP_PATH=os.path.join(DATASET, "danger_pcap")

DEFAULT_BAD_PCAP_PATH=os.path.join(os.path.dirname(os.path.realpath(__file__)), "danger_pcap\\2018-05-03_win12.pcap")

def parse_args():
    desc = "Malicious traffic detection paltform"
    parser = argparse.ArgumentParser(description=desc)  

    parser.add_argument('--updata_goodset',type=bool,default=False,help='是否抓取正常流量数据')
    parser.add_argument('--updata_badset',type=bool,default=False,help='是否更新恶意流量数据')

    parser.add_argument('--num_epoch',type=int,default=5,help='抓取数据流量的次数')
    parser.add_argument('--num_ev',type=int,default=20,help='每次抓取流量包的数量')

    parser.add_argument('--train',action='store_true',required=True,help='训练并输出结果')

    # parser.add_argument('--good_dir',type=GOOD_DATASET_PATH,help='正常流量数据文件存放地址')
    # parser.add_argument('--bad_dir',type=BAD_DATASET_PATH,help='恶意流量数据文件存放地址')
    # parser.add_argument('--bad_pcap_dir',type=BAD_DATASET_PATH,default=DEFAULT_BAD_PCAP_PATH,help='恶意流量数据文件存放地址')
    
    parser.add_argument('--good_dir',type=str,default=str(GOOD_DATASET_PATH),help='正常流量数据文件存放地址')
    parser.add_argument('--bad_dir',type=str,default=str(BAD_DATASET_PATH),help='恶意流量数据文件存放地址')
    parser.add_argument('--bad_pcap_dir',type=str,default=str(DEFAULT_BAD_PCAP_PATH),help='恶意流量数据文件存放地址')

    parser.add_argument('--ignore_warning',type=bool,default=True,help='是否忽略警告')

    args=parser.parse_args()
    validate_args(args)

    return args

def validate_args(args):
    # 打印参数
    print('validating arguments...')
    pprint.pprint(args.__dict__)
    if args.updata_badset:
        assert os.path.exits(args.bad_pcap_dir),'请检查恶意流量pcap文件是否存在'


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
    NAME = ["多项式贝叶斯", "伯努利贝叶斯", "Decision Tree", "Random Forest", "linear regression", "linerSVC", "svc-rbf"]
    for model, modelName in zip(NBM, NAME):
        x_train,y_train=shuffle(x_train,y_train)
        y_train=y_train.ravel()
        y_test=y_test.ravel()
        model.fit(x_train, y_train)
        # 提取性能指标
        f1 = model_selection.cross_val_score(model, x_test, y_test, scoring = 'f1_weighted', cv = 5)
        accu = model_selection.cross_val_score(model, x_test, y_test, scoring = 'precision_weighted', cv = 5)

        print("{} F1 scoring : {}%".format(modelName,round(100 * f1.mean(), 2)))
        print("{} Precision scoring : {}%".format(modelName,round(100 * accu.mean(), 2)))

        joblib.dump(model, './model.pkl')  # 将模型保存到本地

def predicts(x):
    clf = joblib.load('./model.pkl')  # 加载已保存的模型
    return clf.predict(x)

def predicts_pcap(pcap_path):
    x=GetFeature().MakeFeatures(pcap_path)
    return predicts(x)  # true: safe file false: dangerous file

def run(good_filename='train_test/goodx.csv',bad_filename='train_test/badx.csv'):
    goodx=GetFeature().MakeFeatures(good_filename)
    badx=GetFeature().MakeFeatures(bad_filename)
    goody = [1] * len(goodx)
    bady = [0] * len(badx)

    # min_max_scaler = preprocessing.MinMaxScaler()
    # X_train_minmax =min_max_scaler.fit_transform(bady)

    feature_len=len(goodx[0])
    x=np.append(goodx,badx).reshape(-1,feature_len)
    print("特征集大小{}".format(x.shape))
    y=np.append(goody,bady).reshape(-1,1)
    print("输出集大小{}".format(y.shape))


    # 增加对于数值特征和非数值特征的编码
    labels_encoder=[]
    x_encoded = np.empty(x.shape)
    for i,item in enumerate(x[0]):
        if(str(item).isdigit()):
            x_encoded[:,i]=x[:,i]
        else:
            labels_encoder.append(preprocessing.LabelEncoder())
            x_encoded[:, i] = labels_encoder[-1].fit_transform(x[:, i])

    # 为使得数据平均分布，需要进行洗牌
    x,y=shuffle(x,y)
    train(x, y)

def analysis(file_name,save_path,num_epoch=20,num_ev=50):
    # 解析pcap流量包，并存储在save_path
    warnings.filterwarnings("ignore")  
    pcap_path=file_name
    get_badx=GetBadx(save_path,pcap_path,num_epoch*num_ev)
    get_badx.get()
    # 预测
    return bool(predicts_pcap(save_path))


def main():
    args=parse_args()
    if args.ignore_warning:
        warnings.filterwarnings("ignore")  # 忽略警告
    if args.updata_goodset:
        # 获取正样本
        get_goodx=GetGoodx(args.good_dir,args.num_epoch,args.num_ev)
        get_goodx.get()
    if args.updata_badset:
        # 获取负样本
        get_badx=GetBadx(args.bad_dir,args.bad_pcap_dir,args.num_epoch*args.num_ev)
        get_badx.get()  
    if args.train:
        run(args.good_dir,args.bad_dir)

if __name__=="__main__":
    main()