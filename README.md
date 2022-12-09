# TACIoT
Trusted Acess Control for IoT Data in Cloud using Enclaves

## Important note
This current version might be unstable. Go back to commit eedcab5, where aggregation was
not implemented yet, to benchmark system performance.

## Requirements
In order to run the project, you have to:
* Install SGX SDK.
* Enable your SGX device in BIOS (and in software, if necessary).
* Install SGX Driver and SGX PSW.
* Enter your SDK repository and run the following command to set your environment variables:
```
source environment
```
* Clone the following repository: https://github.com/yhirose/cpp-httplib.git.
* Set the application environment variables in the config_macros.h file.
* Enter this repository and run:
```
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./client/sample_libcrypto/
```
* For benchmarking, we leverage wrk2 tool, available at https://github.com/giltene/wrk2.
* Enter the repository and install the tool runing:
```
make
```
* Include wrk binary in the path by running:
```
sudo cp ./wrk /usr/bin/
```

## Usage
To install the project:
```
make LATENCY=0 DEBUG=1
```
Changing the latency value to any non negative integer value allows you to simulate 
network latency in miliseconds for each sent or received message from the server.

To test the server data publishing and quering service, run:
```
./Server s
```
You can use *s* for a secure server (using SGX enclaves) or *i* for an insecure server.
Then, in other configured machine/environment, run:
```
./Client publish 123456 250 72d41281
```
This command publishes a data of type 123456, payload 250 and allow permission for client with ID 72d4128.

For evaluating throughput and latency, you can enter wrk2 repo and run:
```
../wrk2/wrk -t1 -c1 -d30s -R1 "http://localhost:7778/publish/size=631/pk|72d41281|type|555555|size|62|encrypted|dd-b1-b6-b8-22-d3-9a-76-1c-b6-c0-30-6a-e9-21-5a-00-00-00-00-00-00-00-00-00-00-00-00-73-e3-a6-f9-52-d2-97-a3-c1-10-f3-c5-05-cb-8e-1d-8b-e2-cf-cc-16-26-2c-4f-83-94-e4-9a-e0-ee-b3-9c-50-63-68-4d-21-12-f0-a6-12-bc-86-9d-e1-a3-9b-d9-f9-31-d2-7c-63-e3-40-0e-08-17-d3-d2-f8-bf-bf-c0-ee-ea-4c-b7-90-df-"
```
```
./wrk -t2 -c10 -d30s -R200 "http://localhost:7778/query/size=24/pk|72d41281|index|000000"
```
This command creates two threads holding 10 connections. They send 200 requests/sec
during 30 secs of running.