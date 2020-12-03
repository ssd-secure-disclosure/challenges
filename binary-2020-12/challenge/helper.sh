#!/bin/bash 

#LD_PRELOAD="./libc.so.6 ./libpthread.so" ./ld.so ./checker
LD_PRELOAD="./libc-2.23.so ./libpthread-2.23.so" ./ld-2.23.so ./checker
#./checker
