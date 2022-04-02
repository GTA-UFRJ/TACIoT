# TACIoT
Trusted Acess Control for IoT Data in Cloud using Enclaves

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
make LATENCY=0
```
Changing the latency value allow us to any non negative integer value allows you to add
some networking latency in miliseconds for each sent or received message from server.

To test the register application, first, run:
```
./Client
```
The client will offer an attestation service for the server. In other configured
machine/terminal, run:
```
./Server
```
To test the server data publishing service, run:
```
./Publish s
```
You can use *s* for a secure server (using SGX enclaves) or *i* for an insecure server.
Then, in other configured machine/environment, run:
```
./Send
```
To test the SGX Query application, run:
```
./Query
```
For evaluating throughput and latency, you can enter wrk2 repo and run:
```
./wrk -t2 -c10 -d30s -R200 "http://localhost:7778/publish/size=631/pk|72d41281|type|123456|size|62|encrypted|0xdd--0xb1--0xb6--0xb8--0x22--0xd3--0x9a--0x76--0x1c--0xb6--0xc0--0x30--0x6a--0xe9--0x21--0x5a--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x00--0x73--0xe3--0xa6--0xf9--0x52--0xd2--0x97--0xa3--0xc1--0x10--0xf3--0xc5--0x05--0xcb--0x8e--0x1d--0x8b--0xe2--0xcf--0xcc--0x16--0x26--0x2c--0x4f--0x83--0x94--0xe4--0x9a--0xe0--0xee--0xb3--0x9c--0x50--0x63--0x68--0x4d--0x21--0x12--0xf0--0xa6--0x12--0xbc--0x86--0x9d--0xe1--0xa3--0x9b--0xd9--0xf9--0x31--0xd2--0x7c--0x63--0xe3--0x40--0x0e--0x08--0x17--0xd3--0xd2--0xf8--0xbf--0xbf--0xc0--0xee--0xea--0x4c--0xb7--0x90--0xdf--"
```
This command creates two threads holding 10 connections. They send 200 requests/sec
during 30 secs of running.