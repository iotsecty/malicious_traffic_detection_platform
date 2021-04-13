#!/usr/bin/env python
# -*- coding:utf-8 -*-


#"读取30s内的流量信息,并存储进pcap文件"

from scapy.all import *
import os

# 数据包回调函数，显示TCP信息
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("[*] Server: %s" % packet[IP].dst)
            print("[*] %s" % packet[TCP].payload)

# 开启嗅探器，过滤出tcp协议，一次抓5秒，
package=sniff(filter="tcp", timeout=5, prn=packet_callback, store=1)

fileName = "test.pcap"
wrpcap(fileName, package)  #将抓取到的包保存为test.pcap文件
