#!/usr/bin/python
# -*- coding: utf-8 -*-


from __future__ import print_function
import sys
import socket
import csv

# protocol目录
PROTOCOL_PATH = './protocol'

# 监听的网卡，在vmware里的网卡一般是eth30或者eth20,windows系统下需要自己查找，也可以为设置为None
# NETWORK_INTERFACE = None
NETWORK_INTERFACE = 'Intel(R) Dual Band Wireless-AC 3165'

# 需要安装的Python依赖包，注意：如果是开启上报且异步上报的话，还需要安装aiohttp
NEED_INSTALL = ['scapy']


class PcapDecode:
    def __init__(self):
        # ETHER:读取以太网层协议配置文件
        with open('%s/ETHER' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = {}
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]  # 将配置文件中的信息(0257:Experimental)存入dict

        # IP:读取IP层协议配置文件
        with open('%s/IP' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = {}
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]  # 将配置文件中的信息(41:IPv6)存入dic

        # PORT:读取应用层协议端口配置文件
        with open('%s/PORT' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = {}
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]  # 如：21:FTP

        # TCP:读取TCP层协议配置文件
        with open('%s/TCP' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = {}
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]  # 465:SMTPS

        # UDP:读取UDP层协议配置文件
        with open('%s/UDP' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = {}
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]  # 513:Who

    # 解析以太网层协议 ---ether_decode——ip_decode(tcp_decode or udp_decode)
    def ether_decode(self, p):
        data = {}  # 解析出的信息以dict的形式保存
        if p.haslayer("Ether"):  # scapy.haslayer,将pcap包中的信息分层，再处理
            data = self.ip_decode(p)  # 解析IP层协议
            return data
        else:
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
            data['source_ip'] = ''
            data['dest_ip'] = ''
            data['protocol'] = ''
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            data['source_port'] = ''
            data['dest_port'] = ''
            return data

    # 解析IP层协议
    def ip_decode(self, p):
        data = {}
        if p.haslayer("IP"):  # 2048:Internet IP (IPv4) ，分IPV4和IPV6和其他协议
            ip = p.getlayer("IP")
            if p.haslayer("TCP"):  # 6:TCP
                data = self.tcp_decode(p, ip)
                return data
            elif p.haslayer("UDP"):  # 17:UDP
                data = self.udp_decode(p, ip)
                return data
            else:
                if ip.proto in self.IP_DICT:  # 若ip分层中的协议信息在字典中，则提取ip分层中的源地址、目的地址、协议（转换）等
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['source_ip'] = ip.src
                    data['dest_ip'] = ip.dst
                    data['protocol'] = self.IP_DICT[ip.proto]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    data['source_port'] = 'UnKnow'
                    data['dest_port'] = 'UnKnow'
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['source_ip'] = ip.src
                    data['dest_ip'] = ip.dst
                    data['protocol'] = 'IPv4'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    data['source_port'] = 'UnKnow'
                    data['dest_port'] = 'UnKnow'
                    return data
        elif p.haslayer("IPv6"):  # 34525:IPv6
            ipv6 = p.getlayer("IPv6")
            if p.haslayer("TCP"):  # 6:TCP
                data = self.tcp_decode(p, ipv6)
                return data
            elif p.haslayer("UDP"):  # 17:UDP
                data = self.udp_decode(p, ipv6)
                return data
            else:
                if ipv6.nh in self.IP_DICT:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['source_ip'] = ipv6.src
                    data['dest_ip'] = ipv6.dst
                    data['protocol'] = self.IP_DICT[ipv6.nh]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    data['source_port'] = 'UnKnow'
                    data['dest_port'] = 'UnKnow'
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['source_ip'] = ipv6.src
                    data['dest_ip'] = ipv6.dst
                    data['protocol'] = 'IPv6'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    data['source_port'] = 'UnKnow'
                    data['dest_port'] = 'UnKnow'
                    return data
        else:
            if p.type in self.ETHER_DICT:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                data['source_ip'] = p.src
                data['dest_ip'] = p.dst
                data['protocol'] = self.ETHER_DICT[p.type]
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                data['source_port'] = 'UnKnow'
                data['dest_port'] = 'UnKnow'
                return data
            else:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                data['source_ip'] = p.src
                data['dest_ip'] = p.dst
                data['protocol'] = hex(p.type)  # 若在字典中没有改协议，则以16进制的形式显示
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                data['source_port'] = 'UnKnow'
                data['dest_port'] = 'UnKnow'
                return data

    # 解析TCP层协议
    def tcp_decode(self, p, ip):
        data = {}
        tcp = p.getlayer("TCP")
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['source_ip'] = ip.src
        data['dest_ip'] = ip.dst
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        data['source_port'] = str(ip.sport)
        data['dest_port'] = str(ip.dport)
        if tcp.dport in self.PORT_DICT:  # 若端口信息在PORT_DICT\TCP_DICT中则转换为已知
            data['protocol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['protocol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['protocol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['protocol'] = self.TCP_DICT[tcp.sport]
        else:
            data['protocol'] = "TCP"
        return data

    # 解析UDP层协议
    def udp_decode(self, p, ip):
        data = {}
        udp = p.getlayer("UDP")
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['source_ip'] = ip.src
        data['dest_ip'] = ip.dst
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        data['source_port'] = str(ip.sport)
        data['dest_port'] = str(ip.dport)
        if udp.dport in self.PORT_DICT:  # 若端口信息在PORT_DICT\UDP_DICT中则转换为已知
            data['protocol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['protocol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['protocol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['protocol'] = self.UDP_DICT[udp.sport]
        else:
            data['protocol'] = "UDP"
        return data


def get_host_ip():
    """
    查询本机ip地址
    :return: ip
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


def get_host_name():
    """
    查询本机hostname，如果是：xxx.novalocal，则只获取xxx
    """
    hostname = socket.gethostname()
    name = hostname.split('.')[0] if '.' in hostname else hostname
    return name


def handle_flow(obj, data):
    # 解析流量数据
    data1 = obj.ether_decode(data)
    data2 = obj.ip_decode(data)
    data3 = obj.tcp_decode(data,obj[IP])
    data4 = obj.udp_decode(data,obj[IP])

    data=dict(data1.items()+data2.items()+data3.items()+data4.items())
    print(data)
    return data


def check_import(name):
    try:
        exec("import %s" % name)
        return 0, 'success'
    except:
        return 1, 'Python模块%s未安装' % name

def save_IP(package,filename_IP):
    with open(filename_IP,'a') as f:
        f.write("{} {}\n".format(package[IP].src,package[IP].dst))

def check_init():
    if sys.version_info < (3, 0):
        return 1, '该脚本只能在Python3下运行，请使用Python3运行该脚本'

    for app_name in NEED_INSTALL:
        (code, msg) = check_import(app_name)
        if code:
            return 1, msg
        print('Python模块%s已安装' % app_name)

    return 0, 'success'


if __name__ == '__main__':
    PD = PcapDecode()

    host_ip = get_host_ip()
    host_name = get_host_name()

    Sample_num=2  # 正样本的采样周期数
    count=5 # 每次采集的数据包的个数


    print('------------------------------------------------------\r\n')
    print('开始检测是否安装依赖')
    (code, msg) = check_init()
    if code:
        print(msg)
        sys.exit(1)

    loop = None
    from scapy.all import *

    print('------------------------------------------------------\r\n')
    print('主机IP： ', host_ip)
    print('主机名称：', host_name)
    print('监听网卡：', NETWORK_INTERFACE)
    print('------------------------------------------------------\r\n')
    print('开始监控流量数据')
    print('------------------------------------------------------\r\n')

    # 实时抓取流量数据并且每个数据包进行解析输出和上报
    for i in range(Sample_num):
        package=sniff(iface=NETWORK_INTERFACE, count=count, store=1, prn=lambda x:x.summary())
        for i in range(count):
            data=PD.ether_decode(package[i])
            with open('goodx.csv','a') as f:
                [f.write("{0}:{1},".format(key,value)) for key,value in data.items()]
                f.write("\n")
        # print("已经抓取了{}个数据包".format(i*count))


