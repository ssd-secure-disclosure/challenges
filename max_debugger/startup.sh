#!/bin/bash

socat TCP-LISTEN:2326,reuseaddr,fork EXEC:"python3 -u /home/ctf/program.py" 


