#!/bin/bash
rounds=10
results_path="./benchmark/secure_query_throughput.txt"
results_2_path="./benchmark/query_throughput.txt"
if [ -f "$results_path" ]; then
    rm $results_path 
fi
touch $results_path
if [ -f "$results_2_path" ]; then
    rm $results_2_path    
fi
touch $results_2_path
source ../sgxsdk/environment
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/guiaraujo/TACIoT/client/sample_libcrypto/
ps -ef | grep ./Query | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
make clean
TIMEFORMAT=%R
make LATENCY=10 >> /dev/null 2>&1

for clients in 1 10 50 100 200 500;
do
    for round in $(seq 1 $rounds);
    do
        echo "Iniciando round $round (clientes = $clients)" >> $results_path
        echo "Start: $(date '+%M %s %N')" >> $results_path
        for i in $(seq 1 $clients)
        do
            ./Query > /dev/null 2>&1 &
        done
        finish=$(ps aux | grep Query | wc -l)
        while [ $finish -gt 1 ]; do
            finish=$(ps aux | grep Query | wc -l)
        done
        echo "Finish: $(date '+%M %s %N')" >> $results_path
        ps -ef | grep ./Query | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
        sleep 2
    done
done

for clients in 1 10 50 100 200 500;
do
    for round in $(seq 1 $rounds);
    do
        echo "Iniciando round $round (clientes = $clients)" >> $results_2_path
        echo "Start: $(date '+%M %s %N')" >> $results_2_path
        for i in $(seq 1 $clients)
        do
            ./Query 2 > /dev/null 2>&1 &
        done
        finish=$(ps aux | grep Query | wc -l)
        while [ $finish -gt 1 ]; do
            finish=$(ps aux | grep Query | wc -l)
        done
        echo "Finish: $(date '+%M %s %N')" >> $results_2_path
        ps -ef | grep ./Query | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
        sleep 2
    done
done
make clean