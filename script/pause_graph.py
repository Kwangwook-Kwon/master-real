import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import csv

pause_num=[];
data_40G = pd.read_csv("40Gto1G.log")
data_25G = pd.read_csv("25Gto1G.log")
data_10G = pd.read_csv("10Gto1G.log")

print(data_40G)


#pause_num.append( data_40G['pause_num'])




#print(data)


plt.subplot(3,1,1)
plt.title("Number of Pause packet per 100ms")
plt.plot(data_40G['time'],data_40G[' pause_num'], label="40G")
plt.plot(data_25G['time'],data_25G[' pause_num'], label="25G")
plt.plot(data_10G['time'],data_10G[' pause_num'], label="10G")


plt.subplot(3,1,2)
plt.title("Pause Duration per 100ms")
plt.plot(data_40G['time'],data_40G[' pause_duration'], label="40G")
plt.plot(data_25G['time'],data_25G[' pause_duration'], label="25G")
plt.plot(data_10G['time'],data_10G[' pause_duration'], label="10G")

plt.subplot(3,1,3)
plt.title("Pause Transition per 100ms")
plt.plot(data_40G['time'],data_40G[' pause_transition'], label="40G")
plt.plot(data_25G['time'],data_25G[' pause_transition'], label="25G")
plt.plot(data_10G['time'],data_10G[' pause_transition'], label="10G")
#plt.ylim([0,750])
#plt.xlim([0,1000])

#plt.subplot(2,1,2)
#plt.rcParams["figure.figsize"] = (13,2)
#for i in flowRange:
#    plt.plot(th_flow[i-1]['time']*1000-2000,th_flow[i-1]['throughput'])
#plt.ylim([0,1.5])
#plt.xlim([0,1000])		


#plt.subplot(2,1,1)
#for i in flowRange:
#    print(flow[i-1]['time'])
#    plt.plot(flow[i-1]['time']*1000-2000,flow[i-1]['rtt']*1000000,label="flow"+str(i))
#plt.legend(prop={'size':10})
#plt.ylim([0,100])
#plt.xlim([0,1000])
plt.legend(loc=3,fontsize="small")


#print (meanFCT)
#print(test_data)

plt.show()

