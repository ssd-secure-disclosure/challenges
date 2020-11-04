#!/bin/bash
socat -t20 -T20 TCP-LISTEN:2323,reuseaddr,fork EXEC:"/home/ctf/friend_net"
