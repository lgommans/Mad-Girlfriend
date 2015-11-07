#!/usr/bin/env bash

if [ $# -ne 2 ]; then
	echo 'Usage: update-binaries.sh $remote $path'
	echo 'E.g.: update-binaries.sh root@192.168.36.11 /opt/madgirlfriend'
	exit 2
fi

scp madgirlfriend.py alertgenerator.py packetparser.py $1:$2

