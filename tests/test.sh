#!/bin/bash
clients=100
delay=$(( 1000 / $clients ))
for i in $(seq 1 $clients)
do
    initialTime=$(date +%s%N | cut -b1-13)
    while [ $(($current-$initialTime)) -lt $delay ]
    do
	    current=$(date +%s%N | cut -b1-13)
    done
    ./Send > /dev/null 2>&1 &
done