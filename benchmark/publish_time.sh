#!/bin/bash
rounds=10
results_path="./benchmark/publish_time.txt"
if [ -f "$results_path" ]; then
    rm $results_path    
fi
touch $results_path
make clean

for round in $(seq 1 $rounds);
do
    echo "Iniciando round $round (processa = N)" >> $results_path
    make LATENCY=0 >> /dev/null 2>&1
    make Publish LATENCY=0 >> /dev/null 2>&1
    ./Publish >> $results_path
    make clean
done


for round in $(seq 1 $rounds);
do
    echo "Iniciando round $round (processa = S)" >> $results_path
    make LATENCY=0 >> /dev/null 2>&1
    make Publish LATENCY=0 >> /dev/null 2>&1
    ./Publish 2 >> $results_path
    make clean
done
