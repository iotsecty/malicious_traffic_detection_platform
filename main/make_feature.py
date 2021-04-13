#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
该函数的目的是三种log处理,分别将连接日志,SSL日志和证书日志中的相同的id所对应的
(源IP...)
id1  (源IP,...)
id2  (源IP,...)
id3  (源IP,...)
将其存储在../feature/feature+str_n.txt
"""
import re

log_list=['connection_log','ssl_log','certification_log']

def  Get_log_single(n):
    """
    抽取编号为n的流量的三种日志文件的特征
    """
    data_all = {}
    data_ev = {}

    str_n=str(n)

    print("开始提取")
    for i in log_list:
        with open("../log/"+log_list[i]+"/"+log_list[i]+str_n) as f:
            count = 0
            newline = ''
            totalline=''
            # 根据正则将匹配到多行数据组成一行日志。
            for line in f.readlines():
                patt = r'.*(ERROR|WARN|INFO).*'  # 需要改动为所需的特征
                pattern = re.compile(patt)
                result = pattern.findall(line)
                print("----------------------------", type(result))
                if "" == newline or 0 == len(result):
                    newline = newline + " " + line.strip('\n')  # 拼接
                    print('warning:第{}个流量包没有所需的特征!'.format(n))
                    continue
                else:
                    # 判断当前行中有没有匹配的字符串
                    patt = r'.*with=netbeans.*'
                    pattern = re.compile(patt)
                    # 如果当前行匹配到字符串，将该行数据赋值给result2，如果没有匹配到将空数组赋值给result2
                    result2 = pattern.findall(newline)
                    if len(result2)>0:
                        # 对匹配到的数据根据正则方式进行分段。
                        log = re.split("\s", newline)
                        print("-----------------", newline)
                        print("---------------------log类型", type(log))
                        # 在分割字符串后，取出需要的数据。
                        data_ev["date"] = log[3] + log[4]
                        data_all[count] = data_ev

                        print("已取出", count, "行")
                        print("匹配到的时间----------------------", data_ev)
                        count += 1
                    newline = line.strip('\n')
        filename="../feature."+str_n+".txt"
        with open(filename,'w') as feature_file:
            feature_file.write(totalline)



def Get_log_multi(FILE_NUM):
    """"
    :param FILE_NUM: 流量样本的个数
    :return: 操作成功 True 操作失败 False
    """
    try:
        for i in range(FILE_NUM):
            Get_log_single(i)
    except:
        return False
    return True

if __name__=='__main__':
    Get_log_multi()

