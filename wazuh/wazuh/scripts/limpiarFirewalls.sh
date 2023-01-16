#!/bin/bash

for i in $(seq 240 245);
	do 
		sshpass -f password ssh -o StrictHostKeyChecking=no root@192.168.43.$i iptables --flush
		echo "IPTABLES limpiado $i..."
	done
echo "Listo!!"
