#!/bin/bash

while true
do
	echo "Starting Program..."
	socat TCP-LISTEN:2324,reuseaddr,fork EXEC:"./helper.sh"
done
