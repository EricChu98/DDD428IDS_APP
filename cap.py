# -*- coding: utf-8 -*-
import pyshark,time
'''signal_cap = 1  #捕获器运行开关信号
temp = []  #抓来的包缓存池
maxsize = 1000  #缓存池满阈值，待探索合适值
temp_print=[]'''
def capture_cap(): #捕获数据包
    print('in capture_cap!!')
    a = 0
    while True:
        a = a + 1
        #print("第" + str(a) + "次抓包")
        #print(len(temp))
        cap = pyshark.LiveCapture(interface='1', only_summaries=True)
        cap.sniff(timeout=2)
        #print(temp)
        for i in range(len(cap)):
                print(str(cap[i]))
                time.sleep(0.2)
if __name__ == '__main__':
    capture_cap()