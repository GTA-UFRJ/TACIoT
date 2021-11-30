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
./Server
```