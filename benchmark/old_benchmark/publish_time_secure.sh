#!/bin/bash
rounds=10
results_path="./benchmark/secure_publish_time.txt"
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

for round in $(seq 1 $rounds);
do
    echo "Iniciando round $round" >> $results_path
    ./Publish s &>> $results_path &
    echo "Start: $(date '+%M %s %N')" >> $results_path
    ./Send > /dev/null 2>&1 &
    finish=$(ps aux | grep Send | wc -l)
    while [ $finish -gt 1 ]; do
        finish=$(ps aux | grep Send | wc -l)
    done
    echo "Finish: $(date '+%M %s %N')" >> $results_path
    ps -ef | grep ./Send | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
    ps -ef | grep ./Publish | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
    sleep 1
done

make clean