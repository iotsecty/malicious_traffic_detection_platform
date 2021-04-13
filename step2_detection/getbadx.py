#!/usr/bin/env python
# -*- coding:utf-8 -*-

import scapy.all as scapy

from get_goodx import PcapDecode

NUM_BAD=100000 # 恶意流量样本的数量
#注 恶意流量样本的命名 “bad1.pcap”..."badn.pcap"

if __name__=="__main__":
    PD=PcapDecode()
    for i in range(NUM_BAD):
        packets=scapy.rdpcap("bad"+str(i)+".pcap")
        for j in range(sizeof(packets)):
            data=PD.ether_decode(packets[j])
            with open('badx.csv','a') as f:
                [f.write("{0}:{1},".format(key,value)) for key,value in data.items()]
                f.write("\n")