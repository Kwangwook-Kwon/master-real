#!/bin/bash
#!/usr/bin/expr
current_date=$(date "+%Y%m%d_%H%M%S")
echo
echo "output file is gennerated as ${current_date}_output.txt"
echo

echo "time, pause_num, pause_duration, pause_transition" >> ${current_date}_output.log

start_time=$(date "+%s%N")
prev_pause_num=$(ethtool -S enp1s0f1 |grep "rx_prio3_pause:" | awk '{print $2}')
prev_pause_duration=$(ethtool -S enp1s0f1 |grep "rx_prio3_pause_duration:" | awk '{print $2}')
prev_pause_transition=$(ethtool -S enp1s0f1 |grep "rx_prio3_pause_transition:" | awk '{print $2}')

for i in {10..110}
#i=1
#while true
do
    sleep 0.1
    curr_pause_num=$(ethtool -S enp1s0f1 |grep "rx_prio3_pause:" | awk '{print $2}')
    curr_pause_duration=$(ethtool -S enp1s0f1 |grep "rx_prio3_pause_duration:" | awk '{print $2}')
    curr_pause_transition=$(ethtool -S enp1s0f1 |grep "rx_prio3_pause_transition:" | awk '{print $2}')
    
    pause_num=$(expr $curr_pause_num - $prev_pause_num)
    pause_duration=$(expr $curr_pause_duration - $prev_pause_duration)
    pause_transition=$(expr $curr_pause_transition - $prev_pause_transition)
    
    #time=$($i/0.1)
    time=`echo "${i} * 0.1" | bc`
    echo  "$time, $pause_num, $pause_duration, $pause_transition" >> ${current_date}_output.log
    prev_pause_num=$curr_pause_num
    prev_pause_duration=$curr_pause_duration
    prev_pause_transition=$curr_pause_transition
done
