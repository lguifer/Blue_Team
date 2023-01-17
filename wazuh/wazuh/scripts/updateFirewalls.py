import io, re
import json, pdb, subprocess, time
from datetime import datetime

agentList = []
f_agent = io.open('/root/wazuh/scripts/agents.json', mode="r", encoding="latin-1")
path_passwd = "/root/wazuh/scripts/password"

for jsonObj in f_agent:
	eventDict = json.loads(jsonObj)
	agentList.append(eventDict)
f_agent.close()
#cadena1= "sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip_victim+ "sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A INPUT -s "+ip_attacker+" -j ACCEPT"
#command_windows = "netsh advfirewall firewall add rule name="+name_rule_win+" dir=in action=block remoteip="+ip_attacker

for agent in agentList:
	ip = agent["ip"]
	if agent["name"]== "wazuh_master":
		command_linux="iptables --flush"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
		for aux_agent in agentList:
			aux_ip = aux_agent["ip"]
			if aux_agent["name"] != "wazuh_master":
				command_linux="iptables -A INPUT -s "+aux_ip+" -d "+ip+" -j ACCEPT"
				p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
				print(command_linux)				
				command_linux="iptables -A OUTPUT -d "+aux_ip+" -s "+ip+" -j ACCEPT"
				p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
				print(command_linux)
		command_linux="iptables -A INPUT -j  DROP"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
		command_linux="iptables -A OUTPUT -j DROP"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
	elif agent["name"] == "elastic":				
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables --flush"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
		for aux_agent in agentList:
			aux_ip = aux_agent["ip"]
			if aux_agent["name"] == "wazuh_master" or aux_agent["name"]=="wazuh" or aux_agent["name"]=="kibana":
				command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A INPUT -s "+aux_ip+" -d "+ip+" -j ACCEPT"
				p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
				print(command_linux)				
				command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A OUTPUT -d "+aux_ip+" -s "+ip+" -j ACCEPT"
				p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
				print(command_linux)
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A INPUT -j  DROP"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A OUTPUT -j DROP"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)			

     				
	elif agent["name"] == "kibana":				
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables --flush"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
		for aux_agent in agentList:
			aux_ip = aux_agent["ip"]
			if aux_agent["name"] == "wazuh_master" or aux_agent["name"]=="elastic":

				command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A INPUT -s "+aux_ip+" -d "+ip+" -j ACCEPT"
				p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
				print(command_linux)				
				command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A OUTPUT -d "+aux_ip+" -s "+ip+" -j ACCEPT"
				p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
				print(command_linux)
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A INPUT -j  DROP"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A OUTPUT -j DROP"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)				

					
	elif agent["name"] == "suricata":				
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables --flush"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
		for aux_agent in agentList:
			aux_ip = aux_agent["ip"]
			if aux_agent["name"] == "wazuh_master":
				command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A INPUT -s "+aux_ip+" -d "+ip+" -j ACCEPT"
				p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
				print(command_linux)				
				command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A OUTPUT -d "+aux_ip+" -s "+ip+" -j ACCEPT"
				p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
				print(command_linux)
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A INPUT -j  DROP"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)
		command_linux="sshpass -f "+path_passwd+" ssh -o StrictHostKeyChecking=no root@"+ip+ " iptables -A OUTPUT -j DROP"
		p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
		print(command_linux)

