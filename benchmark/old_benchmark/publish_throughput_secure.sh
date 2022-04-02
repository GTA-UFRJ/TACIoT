#!/bin/bash
rounds=10
results_path="./benchmark/secure_publish_throughput.txt"
if [ -f "$results_path" ]; then
    rm $results_path    
fi
touch $results_path
source ../sgxsdk/environment
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/guiaraujo/TACIoT/client/sample_libcrypto/
ps -ef | grep ./Send | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
ps -ef | grep ./Publish | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
make clean
TIMEFORMAT=%R
make LATENCY=0 >> /dev/null 2>&1
rm database/sample

for clients in 1 10 50 100 500 700 1000;
do
    for round in $(seq 1 $rounds);
    do
        echo "Iniciando round $round (clientes = $clients)" >> $results_path
        echo "Start: $(date '+%M %s %N')" >> $results_path
        ./Publish s &>> $results_path &
        delay=$(( 1000 / $clients ))
        for i in $(seq 1 $clients)
        do
            initialTime=$(date +%s%N | cut -b1-13)
            current=$(date +%s%N | cut -b1-13)
            while [ $(($current-$initialTime)) -lt $delay ]
            do
			    current=$(date +%s%N | cut -b1-13)
		    done
            ./Send > /dev/null 2>&1 &
        done
        finish=$(ps aux | grep Send | wc -l)
        while [ $finish -gt 1 ]; do
            finish=$(ps aux | grep Send | wc -l)
        done
        echo "Finish: $(date '+%M %s %N')" >> $results_path
        ps -ef | grep ./Send | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
        ps -ef | grep ./Publish | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
        sleep 1
    done
done

make clean