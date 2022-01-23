#!/bin/bash
rounds=10
results_path="./benchmark/register_time.txt"
if [ -f "$results_path" ]; then
    rm $results_path    
fi
touch $results_path
ps -ef | grep ./Client | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
make clean

for latency in 1 10 50 100;
do
    for round in $(seq 1 $rounds);
    do
        echo "Iniciando round $round (latencia = $latency)" >> $results_path
        make LATENCY=$latency >> /dev/null 2>&1
        ./Client >> /dev/null 2>&1 &
        sleep 2
        { time ./Server > /dev/null 2>&1 ; } 2>> $results_path
        ps -ef | grep ./Client | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
        sleep 1
    done
done
