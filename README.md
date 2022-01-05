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

## Usage
To run the project, follow these steps:
```
make
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:TACIoT_location/client/sample_libcrypto/
./Client
```
In other terminal, repeat the source environment command and then, execute:
```
./Server
```
To test the SGX Publish application:
```
make
make Publish
./Publish
./Publish x
```
