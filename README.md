# TACIoT
Trusted Acess Control for IoT Data in Cloud

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

## Usage
To run the project:
```
make
```
To test the register application, first, run:
```
./Client
```
Then, in other configured machine/environment, run:
```
./Server
```
To test the SGX Publish application, run:
```
./Publish
```
Then, in other configured machine/environment, run:
```
./Send
```
To test the SGX Query application, run:
```
./Query
```

## Commentary
This version is current UNSTABLE when receiving a lot of requests.
We are currently working on some improvments.
The version used to benchmark is the previous (b5ecf4f on Jan 23).