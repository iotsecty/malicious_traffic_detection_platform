Introduction
----------

Name:Encryption malicious traffic analysis and testing platform

### Background

With the popularity of HTTPS in recent years, the proportion of encrypted malicious traffic attacks is gradually increasing. According to the report, at present, the malware for encrypted communication has basically covered all types of attacks, such as Trojan horse, blackmail software, infective, worm virus, downloader, etc. among them, the malware family of Trojan horse and downloader accounts for a relatively high proportion.


 ![The proportion of malware](ImageForReadme/PieChart.png)

The commonly used software encryption communication methods can be roughly divided into six types:


|Type|Means of Attack|
|-------|--------|
|Trojan Horse|C&C direct connection,White stands hidden transfer,Others|
|ransomware|C&C direct connection|
|Infection type software|C&C direct connection,normal discharge|
|worm virus|C&C direct connection,worm propagation|
|downloader|White stands hidden transfer,Others|

### Manual 

```
malicious_traffic_detection_platform.traffic_platform
  |
  |_______ train_test   
  |          |____ dataset
  |          |          |____ badx.csv
  |          |          |____ goodx.csv  
  |          |____ protocol
  |          |          |____ ETHER
  |          |          |____ FILES
  |          |          |____ IP
  |          |          |____ PORT
  |          |          |____ UDP
  |          |          |____ TCP
  |          |          |____ WARN
  |          |____ safe_pcap (Folder)
  |          |
  |          |____ __init__.py
  |          |____ main.py
  |          |____ get_goodx.py
  |          |____ get_badx.py
  |          |____ get_feature.py
  |          |____ 抓包协议分析器.py
  |          |
  |          |____ model.pkl
  |_______ web_platform
  |          |____ __init__.py
  |          |____ runserver.py
  |          |____ setting.py
  |          |____ controller
  |          |____ User_Info.sqlite3
  |          |          |____ ————init__.py
  |          |          |____ message.py
  |          |____ pcap_test(Folder)
  |          |____ static
  |          |          |____ style.css
  |          |____ tempaltes
  |          |          |____ logout.html
  |          |          |____ login.html
  |          |          |____ show_entries.html
  |          |          |____ show_error.html
  |          |          |____ upload.html
  |          |____ model
  |          |          |____ Category.py
  |          |          |____ User.py
  |_______ model.pkl
```

### Current Work

1. Normal flow sample collection based on scapy（ getgoodx.py ）And the analysis of large-scale attack sample packets (pcap);
2. Data cleaning, filtering and Feature Engineering (this is a very difficult step, because the quality of Feature Engineering basically determines the upper limit of model quality)
3. A variety of different machine learning models, based on the business requirements of maintainability and interpretability of security attack and defense system, focus on SVM, random forest and integrated learning algorithm. The landing business scenarios of these three models are very different, which will be explained later.


|Method|F1-Score(%)|Precision(%)|
|------|---------|-----|
|Random Forest|91.01|92.26|
|Bernoulibeyes|89.81|91.3|
|Decision Tree|87.7|90.25|
|linear regression|88.25|88.89|
|linerSVC|77.13|81.57|
|Polynomial Bayesian|64.25|67.27|
|svc-rbf|42.98|34.03|

Among them, the best comprehensive effect is random forest algorithm, F1 score stable at more than 90%, which is the same as [the literature](https://blog.riskivy.com/%e5%9f%ba%e4%ba%8e%e6%9c%ba%e5%99%a8%e5%ad%a6%e4%b9%a0%e7%9a%84%e6%81%b6%e6%84%8f%e8%bd%af%e4%bb%b6%e5%8a%a0%e5%af%86%e6%b5%81%e9%87%8f%e6%a3%80%e6%b5%8b/) said.


### SpotLight

- The first domestic open source analysis and detection platform of encrypted malicious traffic based on machine learning method

- Considering the existing feature engineering as much as possible, and combining with NLP, a new feature engineering method different from word frequency (TF) is proposed

### Todolsit

- [ ] support for a custom neural network model (Deep is all you needed?)
- [ ] not limited to the keyword detection commonly used in the industry. The emotional analysis tools such as nltk are added to NLP to better reflect the statistical characteristics
- [ ] training of larger datasets, supporting relational databases, such as MySQL
- [ ] front end detection page based on the flask framework

If you have any question or suggestion, Please email us :)

### Enviroment



 Support Python 3.0+
 
 You may install Winpcap,if you want to run the section of getting samples,by the way,it's easy to install the software.


CONECTION
-----------
email: **xmfeng2000@126.com**

地址: Xidian University,Xi'an,China


LICENSE
-------
MIT License

Copyright (c) 2021 Xinmin Feng & Mingyi Li