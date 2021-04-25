Introduction
----------
软件名称：加密恶意流量分析与检测平台
### Background

随着近年来HTTPS的普及，加密恶意流量攻击的比例也在逐渐提升。根据报告,目前加密通信的恶意软件基本已经覆盖所有的攻击类型，例如特洛伊木马、勒索软件、感染式、蠕虫病毒、下载器等，其中特洛伊木马和下载器类的恶意软件家族占比较高。

 ![The proportion of malware](./Pictures/PieChart.png)

常用的软件加密通信方式，可以粗略地分为六种：

|Type|Means of Attack|
|-------|--------|
|Trojan Horse|C&C direct connection,White stands hidden transfer,Others|
|ransomware|C&C direct connection|
|Infection type software|C&C direct connection,normal discharge|
|worm virus|C&C direct connection,worm propagation|
|downloader|White stands hidden transfer,Others|

### Current Work

1. 基于Scapy的正常流量样本的采集（getgoodx.py）,以及对于大规模攻击样本数据包的解析(pcap);
2. 数据清洗、过滤和特征工程（这是非常困难的一个步骤，因为特征工程的好坏基本决定了模型的质量上限）
3. 多种不同的机器学习模型,基于安全攻防系统的可维护性和可解释性的业务要求，重点是SVM、随机森林以及集成学习算法，这三者的落地业务场景十分不同,后续版本后说明。

|Method|F1-Score(%)|Precision(%)|
|------|---------|-----|
|Random Forest|91.01|92.26|
|伯努利贝叶斯|89.81|91.3|
|Decision Tree|87.7|90.25|
|linear regression|88.25|88.89|
|linerSVC|77.13|81.57|
|多项式贝叶斯|64.25|67.27|
|svc-rbf|42.98|34.03|

其中，综合效果最好的方法是随机森林算法,F1得分稳定在90%以上,这和[文献](https://blog.riskivy.com/%e5%9f%ba%e4%ba%8e%e6%9c%ba%e5%99%a8%e5%ad%a6%e4%b9%a0%e7%9a%84%e6%81%b6%e6%84%8f%e8%bd%af%e4%bb%b6%e5%8a%a0%e5%af%86%e6%b5%81%e9%87%8f%e6%a3%80%e6%b5%8b/)所说的是相同的。


### SpotLight

- 国内第一款开源的基于机器学习方法的加密恶意流量分析与检测平台
- 尽量多的考虑到了现有的特征工程，并结合NLP给出不同于词频(TF)的崭新的特征工程方法

### Todolsit

- [ ]  支持自定义神经网络模型(Deep is all you need?)
- [ ]  不限于业界常用的关键词检测,加入NLP的情感分析工具,例如NLTK等方法,更好的体现统计特性
- [ ]  更大规模的数据集的训练,支持关系型数据库,例如MySQL
- [ ]  基于Flask框架的前端检测页面


If you have any question or suggestion, Please email us :)

### Enviroment


支持Python3.0及以上的版本。

如果你想运行正负样本数据包采集的代码(getgoodx.py,getbadx.py),你可能需要先下载winpcap软件，这个软件非常容易下载安装，当然你可以使用其他可以接获流量包的软件。

### Deployment procedure
 
Easy to use.....

CONECTION
-----------
email: **xmfeng2000@126.com**

地址: Xidian University,Xi'an,China


LICENSE
-------
MIT License

Copyright (c) 2021 Xinmin Feng & Minyi Li