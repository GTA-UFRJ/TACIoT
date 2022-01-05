#!/bin/bash
rounds=10
results_1_path="./benchmark/publish_throughput_cluster.txt"
results_2_path="./benchmark/publish_throughput_individual.txt"
if [ -f "$results_1_path" ]; then
    rm $results_1_path    
fi
if [ -f "$results_2_path" ]; then
    rm $results_2_path    
fi
touch $results_1_path
touch $results_2_path
ps -ef | grep ./Publish | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
make clean
TIMEFORMAT=%R

for clients in 1 10 50 100 200 500;
do
    for round in $(seq 1 $rounds);
    do
        echo "Iniciando round $round (clientes = $clients)" >> $results_1_path
        echo "Iniciando round $round (clientes = $clients)" >> $results_2_path
        make LATENCY=10 >> /dev/null 2>&1
        make Publish LATENCY=10 >> /dev/null 2>&1
        echo "Start: $(date '+%M %s %N')" >> $results_1_path
        for i in $(seq 1 $clients)
        do
            { time ./Publish 2 > /dev/null 2>&1 ; } 2>> $results_2_path &
        done
        finish=$(ps aux | grep Publish | wc -l)
        while [ $finish -gt 1 ]; do
            finish=$(ps aux | grep Publish | wc -l)
        done
        echo "Finish: $(date '+%M %s %N')" >> $results_1_path
        ps -ef | grep ./Publish | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
        make clean
    done
done
