#!/bin/bash

sshpass -f password ssh -o StrictHostKeyChecking=no root@192.168.43.240 systemctl restart wazuh-manager.service
echo "Reiniciado Wazuh Manager"sshpass -f password ssh -o StrictHostKeyChecking=no root@192.168.43.241 systemctl restart elasticsearch.service
echo "Reiniciado ElasticSearch"
sshpass -f password ssh -o StrictHostKeyChecking=no root@192.168.43.242 systemctl restart kibana.service 
echo "Reiniciado Kibana"
sshpass -f password ssh -o StrictHostKeyChecking=no root@192.168.43.244 systemctl restart suricata.service
echo "Reiniciado Suricata"

for i in $(seq 240 245);
	do 
		sshpass -f password ssh -o StrictHostKeyChecking=no root@192.168.43.$i systemctl restart wazuh-agent.service
		echo "Reiniciado agente $i"
	done
echo Listo!
