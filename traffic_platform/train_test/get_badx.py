#!/usr/bin/env python
# -*- coding:utf-8 -*-

import scapy.all as scapy

from .get_goodx import PcapDecode

NUM_BAD=100000 # 恶意流量样本的数量


class GetBadx():
    def __init__(self,bad_filename,bad_pcap_filename,num):
        self.bad_filename=bad_filename
        self.bad_pcap_filename=bad_pcap_filename
        self.num=num
    def get(self):
        """
        :param bad_filename: 数据包存储位置，需要是csv格式
        :param bad_pcap_filename: pcap包读取位置
        :param num: 读取数据包的数量
        :return: None
        """
        PD = PcapDecode()
        scapy.load_layer('tls')
        with open(self.bad_filename, 'a') as f:
            with scapy.PcapReader(self.bad_pcap_filename) as packets:
                for i, pkt in enumerate(packets):
                    data = PD.ether_decode(pkt)
                    [f.write("{},".format(value)) for key,value in data.items()]
                    # [f.write("{}:{}, ".format(key, value)) for key, value in data.items()]
                    f.write("bad\n")
                    # if (i % 200 == 0):
                    #     print("目前已处理{0}个数据包.".format(i))
                    if i==self.num:
                        print("已经处理{}个恶意文件数据包".format(i))
                        return True


# 基于迭代器的pcap文件解析
if __name__=="__main__":
    bad_filename='./badx.csv'
    bad_pcap_filename="../2018-05-03_win12.pcap"
    get_badx=GetBadx(bad_filename,bad_pcap_filename,10).get()


##另外两种读取pcap包的方式，限于规模较小的情况

# # 大批量恶意数据流量文件解析方式
# if __name__=="__main__":
#     PD=PcapDecode()
#     for i in range(NUM_BAD):
#         packets=scapy.rdpcap("../2018-05-03_win12.pcap")
#         for j in range(sizeof(packets)):
#             data=PD.ether_decode(packets[j])
#             with open('badx.csv','a') as f:
#                 [f.write("{0}:{1},".format(key,value)) for key,value in data.items()]
#                 f.write("\n")


# # 基于scapy.rdpcap的pcap解析实现，太慢了
# if __name__=="__main__":
#     PD=PcapDecode()
#     scapy.load_layer('tls')
#     packets = scapy.rdpcap("../2018-05-03_win12.pcap")
#     num=sizeof(packets)
#     with open('badx.csv', 'a') as f:
#         for j in range(num):
#             data=PD.ether_decode(packets[j])
#             [f.write("{},".format(value)) for key,value in data.items()]
#             f.write("bad\n")
