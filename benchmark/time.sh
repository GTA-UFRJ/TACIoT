#!/bin/bash
results_path="./benchmark/time.txt"
microbenchmark_insecure_path="./benchmark/micro_insecure.txt"
microbenchmark_secure_path="./benchmark/micro_secure.txt"
if [ -f "$results_path" ]; then
    rm $results_path    
fi
if [ -f "$microbenchmark_insecure_path" ]; then
    rm $microbenchmark_insecure_path    
fi
if [ -f "$microbenchmark_secure_path" ]; then
    rm $microbenchmark_secure_path    
fi
touch $results_path
touch $microbenchmark_insecure_path
touch $microbenchmark_secure_path
source ../sgxsdk/environment
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/guiaraujo/TACIoT/client/sample_libcrypto/
ps -ef | grep ./Server | grep -v grep | awk '{print $2}' | xargs kill >> /dev/null 2>&1
make clean
TIMEFORMAT=%R
make LATENCY=0 >> /dev/null 2>&1
rm database/sample
publish_time_command="http://localhost:7778/publish/size=631/pk|72d41281|type|123456|size|62|encrypted|0xdd--0xb1--0xb6--0xb8--0x22--0xd3--0x9a--0x76--0x1c--0xb6--0xc0--0x30--0x6a--0xe9--0x21--0x5a--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x73--0xe3--0xa6--0xf9--0x52--0xd2--0x97--0xa3--0xc1--0x10--0xf3--0xc5--0x05--0xcb--0x8e--0x1d--0x8b--0xe2--0xcf--0xcc--0x16--0x26--0x2c--0x4f--0x83--0x94--0xe4--0x9a--0xe0--0xee--0xb3--0x9c--0x50--0x63--0x68--0x4d--0x21--0x12--0xf0--0xa6--0x12--0xbc--0x86--0x9d--0xe1--0xa3--0x9b--0xd9--0xf9--0x31--0xd2--0x7c--0x63--0xe3--0x40--0x0e--0x08--0x17--0xd3--0xd2--0xf8--0xbf--0xbf--0xc0--0xee--0xea--0x4c--0xb7--0x90--0xdf--"
query_time_command="http://localhost:7778/query/size=24/pk|72d41281|index|000000"
wrk2path="/home/guiaraujo/wrk2/wrk"

echo -e "\n------ ROUND 1 - Insecure publish time ------\n" &>> $results_path

touch database/sample
./Server i >> $microbenchmark_insecure_path &
sleep 1
$wrk2path -t1 -c1 -d120s -R10 $publish_time_command &>> $results_path
./Client s >> /dev/null 2>&1

echo -e "\n------ ROUND 2 - Insecure query time ------\n" &>> $results_path

./Server i >> $microbenchmark_insecure_path &
sleep 1
$wrk2path -t1 -c1 -d120s -R10 $query_time_command &>> $results_path
./Client s >> /dev/null 2>&1
rm database/sample

echo -e "\n------ ROUND 3 - Secure publish time ------\n" &>> $results_path

touch database/sample
./Server s >> $microbenchmark_secure_path &
sleep 1
$wrk2path -t1 -c1 -d120s -R10 $publish_time_command &>> $results_path
./Client s >> /dev/null 2>&1

echo -e "\n------ ROUND 4 - Secure query time ------\n" &>> $results_path

./Server s >> $microbenchmark_secure_path &
sleep 1
$wrk2path -t1 -c1 -d120s -R10 $query_time_command &>> $results_path
./Client s >> /dev/null 2>&1

make clean