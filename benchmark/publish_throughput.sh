#!/bin/bash
rounds=10
results_path="./benchmark/publish_throughput.txt"
if [ -f "$results_path" ]; then
    rm $results_path    
fi
touch $results_path
ps -ef | grep ./Publish | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
make clean
TIMEFORMAT=%R

for clients in 1 10 50 100 200 500;
do
    for round in $(seq 1 $rounds);
    do
        echo "Iniciando round $round (clientes = $clients)" >> $results_path
        make LATENCY=50 >> /dev/null 2>&1
        make Publish LATENCY=50 >> /dev/null 2>&1
        for i in $(seq 1 $clients)
        do
            { time ./Publish 2 > /dev/null 2>&1 ; } 2>> $results_path &
        done
        sleep 5
        ps -ef | grep ./Publish | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
        make clean
    done
done
