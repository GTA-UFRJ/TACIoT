#!/bin/bash
for i in $(seq 1 500)
do
    ./Send > /dev/null 2>&1 &
    #./networking/client_server_tests/client &
done