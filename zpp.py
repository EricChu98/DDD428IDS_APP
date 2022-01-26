import pyshark
import re
# cap = pyshark.LiveCapture(interface='1',only_summaries=True)
# cap.sniff(timeout=3)
# print(cap[0])
# print('hgh')
'''
基础软件逻辑（不包含bug修复和高级功能）：
Module1:捕获器：使用pyshark捕获一条精简数据包，包含来源、目的IP，协议类型等。（我们暂时不分析端口号，因为端口号不好提取）。
              抓到数据包，存入缓存池temp中。temp有最大条目数1000的限制。一旦temp数量达到1000，temp将被清空重写，这也是
              软件的bug所在，有造成严重丢包的后果的可能性。不过后期我们可以通过寻找并合理设定1000这个阈值来降低丢包。
Module2:过滤器之IP黑名单：IP黑名单是我从我的防火墙网站上下载的一个txt文档，列出来了危险IP地址及其无分类子网掩码。该模块负责
              从temp中读取数据包，将每个包与一千多个IP地址进行匹配（只管源、目的IP，其他都不管），如果匹配到则发出报警信号。
              值得注意的是，过滤器从temp中提取IP条目的速度与捕获器写入数据包条目到temp的速度是一个竞争状态。双方同时运行，
              但是会发生以下限制：（1）捕获器检测到temp已满时，不管过滤器匹配到哪一个条目，都直接将temp清空重写。（2）过滤
              器检测到temp中没有条目时会等待。（3）过滤器已经匹配完temp中的条目而捕获器没有写入新的条目时会等待。
Module3:过滤器之Snort规则：Snort规则需要安装Snort，我们无需配置使用Snort，只需要到其安装目录下，找到能用的*.rules文件，
              提取出这个文件中包含的报警规则。（报警规则中我们也只使用源、目的IP和协议类型。）
Module4:报警模块：报警模块拟采用单独线程调用AppleScript在系统上进行通知弹出的操作，同时更新首页的报警数量信息，将报警内容（发
              现的非法IP地址和协议）记录在警报面板中作为表格的一行。
信号传递：1、捕获器、IP过滤器、Snort过滤器这三者需要分别传出一个全局bool变量来表示模块的运行状态，因为主页有状态显示。而且要能
           接受外来的信号写入，更改这些bool来控制模块运行，因为在设置界面有开关。
        2、报警模块需要传出一个全局变量（字典？）来记录报警信息。提取出字典大小，传出给主页警报数量显示。提取出IP和协议，传出给
           警报页面列表显示事件。
'''

'''
软件高级功能：模式设置：允许用户选定进程进行信任，以实现白名单规则，提高效率。
后话
'''

import time
import os
from multiprocessing import Process
from threading import Thread

signal_cap = False  #捕获器运行开关信号
signal_rules = False  #IP规则运行开关信号
temp = []  #抓来的包缓存池
maxsize = 1000  #缓存池满阈值，待探索合适值
black_ips = [] #从txt文件读入的IP规则

def capture_cap(): #捕获数据包
    print('in capture_cap!!')
    global temp
    a = 0
    while True:
        a = a + 1
        print("第" + str(a) + "次抓包")
        cap = pyshark.LiveCapture(interface='1', only_summaries=True)
        cap.sniff(timeout=2)
        print(cap)
        for i in range(len(cap)):
            if len(temp) < maxsize:
                temp.append(str(cap[i]))

# def deal_temp():
#     print('in deal_temp!')
#     global temp
#     global signal_cap
#     while True:
#         if len(temp) >= maxsize and signal_cap == True:
#             temp = []
#             signal_cap = False

def ip_rules():    # 黑名单ip检测
    print('in rules!')
    global temp
    global black_ips
    global signal_cap
    count = 0
    while True:
        if len(temp)==0:  #缓存池空：等待
            count = 0
            continue
        if len(temp) == maxsize and signal_cap == True:  #缓存池满，并且捕获器还在抓包：清除缓存池（看网速，可能严重丢包）
            count = 0
            temp = []
            signal_cap = False
        while count < len(temp):
            pattern = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
            ips = pattern.findall(str(temp[count]))
            if ips == []:  #没匹配到
                continue
            for i in range(len(black_ips)):
                if black_ips[i][0][:black_ips[i][1]] == deal_ip(ips[0])[0][:black_ips[i][1]] or black_ips[i][0][:black_ips[i][1]] == deal_ip(ips[1])[0][:black_ips[i][1]]:
                    warning(temp[count])  #匹配到，报警
            count += 1
            print(count)
        else:
            signal_cap = True  #这可能会导致认为关闭捕获器后捕获器自启动的情况。。待讨论。
def warning(cap):
    print('Warning !!!!!!!'+ str(cap))  #报警。应该包含弹出通知，传出非法数据包的信息。

def deal_ip(ip):  #为了适应规则中带的无分类子网掩码，需要将IP转成二进制字符串进行逐位匹配，ip_len是前缀长度（匹配长度）
    ip = ip.replace('\n','')
    if ip.find('/') == -1:
        ip += '/32'
    ip , ip_len = ip.split('/')
    ip = ip.split('.')
    ip_bin = ''
    for i in range(4):
        ip_bin += bin(int(ip[i]))[2:].zfill(8)
    return [ip_bin,int(ip_len)]


def update_black_ips():  #更新黑名单ip列表，读取文件，重写black_ips
    global black_ips
    ips = open('/Users/zhuguangyi/Assignment/DDD428IDS/emerging-Block-IPs.txt').readlines()
    pattern = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
    for i in range(len(ips)):
        ip = pattern.findall(ips[i])
        if ip != []:
            black_ips += [deal_ip(ips[i])]

if __name__ == '__main__':
    ip1 = '127.0.0.1\n'  #试验规则，可以是自己的IP，用来触发报警。
    print(deal_ip(ip1))
    update_black_ips()
    print(black_ips[:5])
    print(len(black_ips))
    cap = pyshark.LiveCapture(interface='1', only_summaries=True)
    cap.sniff(timeout=2)
    print(cap)
    for i in range(len(cap)):  #给定初始数据包，也可以不要
        temp.append(str(cap[i]))




    threads = [] #多线程运行，每个模块必须是一个独立线程。

    #捕获数据包线程和ip检测进程同时运行
    thd1 = Thread(target=capture_cap)
    threads.append(thd1)

    thd2 = Thread(target=ip_rules)
    threads.append(thd2)

    thd1.start()
    thd2.start()
    # capture_cap()




