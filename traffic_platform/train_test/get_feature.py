#!/usr/bin/env python
# -*- coding:utf-8 -*-
import numpy as np
from datetime import datetime


# # 加载文件
# def LoadFile():
#     badXss='./badx.csv'
#     goodXss='./goodx.csv'
#     bf=[x.strip().lower() for x in open(badXss,'r').readlines()]
#     gf=[x.strip().lower() for x in open(goodXss,'r').readlines()]
#     return bf,gf

# dict={(source_ip,dest_ip):[[len1,len2,len3...][start_time,time1,time2,...],[IPv6/IP, 'TCP'/'UDP',DNS Qry/Ans],[source_port,dest_port]],...}
# 还可以统计ARP地址解析协议的出现频率
# 现在根据情况，首先实现长度和时间
class GetFeature():
    def __init__(self):
        pass

    def MakeFeatures(self,file_name):
        dict = {}
        feature=[]
        protocol_list=['IP','UDP','DNS ANS','DNS Qry','IPV6','ICMPv6','TLS']
        with open(file_name) as f:
            for line in f.readlines():
                x=line[:-1].split(',')

                if x[3].isdigit():
                    x[3]=int(x[3])
                else:
                    x[3]=int(x[4])
                flag=3
                if x[1]=="" or x[2]=="":

                    continue
                if(((x[1],x[2]) not in dict)&((x[2],x[1]) not in dict)):
                    # 初始化一个对话数据历史
                    dict[(x[1], x[2])]=[]
                    dict[(x[1],x[2])].append([x[3]])
                    dict[(x[1],x[2])].append([x[0]])
                    dict[(x[1], x[2])].append({}) #存放协议
                    dict[(x[1], x[2])].append([]) #存放用到的端口

                    for item in protocol_list:
                        dict[(x[1], x[2])][2][item]=0
                    flag=0
                elif ((x[1],x[2]) in dict):
                    flag=1
                    dict[(x[1], x[2])][0].append(x[3])
                    dict[(x[1], x[2])][1].append(x[0])
                elif ((x[2],x[1]) in dict):
                    flag=2
                    dict[(x[2], x[1])][0].append(x[3])
                    dict[(x[2], x[1])][1].append(x[0])
                if flag==1:
                    for item in protocol_list:
                        if (item in x[4])or(item in x[5]):
                            dict[(x[1], x[2])][2][item] +=1
                elif flag==2:
                    for item in protocol_list:
                        if (item in x[4])or(item in x[5]):
                            dict[(x[2], x[1])][2][item] +=1
                elif flag!=0:
                    print('异常数据: {}'.format(line))
                    continue


                if x[-1]=='bad':
                    source_port=x[-3]
                    dest_port=x[-2]
                else:
                    source_port=x[-4]
                    dest_port=x[-3]

                if flag==1:
                    dict[(x[1], x[2])][3].append([source_port, dest_port])
                elif flag==2:
                    dict[(x[2], x[1])][3].append([source_port, dest_port])

# 处理特征 feature=[[len_mean,len_std,time_mean,time_std,frequence of'IP','UDP','DNS ANS','DNS Qry','IPV6',len_APR_mean,len_APR_std]]

        for key in dict:
            time_list=[]
            current_list=[]
            len_mean=np.mean(dict[key][0])
            len_std=np.std(dict[key][0])
            for i,item in enumerate(dict[key][1]):
                if i==0:
                    time_s=datetime.strptime(item,"%Y-%m-%d %H:%M:%S")
                    time_list.append(0)
                else:
                    time_c=datetime.strptime(item,"%Y-%m-%d %H:%M:%S")
                    time_list.append((time_c-time_s).seconds)
            # time_list=[0,3,4,7,9,...]
            time_mean=np.mean(time_list)
            time_std=np.var(time_list)
            # 记录空端口的数量
            num_unkown=0
            for item in dict[key][3]:
                if item=='UnKnow':
                    num_unkown+=1

            current_list=[len_mean,len_std,time_mean,time_std,num_unkown]
            for item in protocol_list:
                current_list.append(dict[key][2][item])
            feature.append(current_list)
        return feature

if __name__=="__main__":
    filename='./goodx.csv'
    feature=GetFeature().MakeFeatures(filename)
    print(feature)