#!/bin/bash

export TERM=xterm
socat TCP-LISTEN:2325,reuseaddr,fork EXEC:"./cobra_kai"
