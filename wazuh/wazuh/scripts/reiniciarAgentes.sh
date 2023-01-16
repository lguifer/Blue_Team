#!/bin/bash

for i in $(seq 240 245);
	do 
		sshpass -f password ssh -o StrictHostKeyChecking=no root@192.168.43.$i systemctl restart wazuh-agent.service
		echo "Reiniciado agente $i"
	done
echo Listo!
