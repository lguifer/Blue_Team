import io
import json, pdb, subprocess, time
from datetime import datetime

eventsList = []
agentList = []
current_time = ""
IGNORE = False
#print("Started Reading JSON file which contains multiple JSON document")
f_time = io.open("timestamp", mode="r", encoding="latin-1")
#with open('timestamp',"r") as f_time:
for tiempo in f_time:
	current_time = tiempo.strip()
	current_time = current_time[0:-9]
	print("Current: ", current_time)
	current_time = datetime.strptime(current_time,"%Y-%m-%dT%H:%M:%S")
f_time.close()		
while True:
	eventsList.clear()
	agentList.clear()
	try:

		f = io.open('/var/ossec/logs/alerts/alerts.json', mode="r", encoding="latin-1")
		f_agents = io.open('agents.json', mode="r", encoding="latin-1")

		#with open('/var/ossec/logs/alerts/alerts.json') as f:
		for jsonObj in f:
			eventDict = json.loads(jsonObj)
			eventsList.append(eventDict)
		f.close()		
		for jsonObj in f_agents:
			eventDict = json.loads(jsonObj)
			agentList.append(eventDict)
		f.close()		
		#pdb.set_trace()
		#print("Printing each JSON Decoded Object", agentList)
	except:
		#print("Error leyendo eventos JSON: ")
		time.sleep(0.1)
		continue
	for event in eventsList:
		#print(event["timestamp"])
		timestamp = event["timestamp"].strip()
		last_time = timestamp[0:-9]
		#print("time: ", last_time)
		captured_time = datetime.strptime(last_time,"%Y-%m-%dT%H:%M:%S")
		ruleID = event["rule"]["id"]
		#print("RUle: ", ruleID)
		name_rule_win=""
		if ruleID == "100006" or ruleID == "100007" or ruleID=="100004" or ruleID=="100008" :
			if current_time == "":
				current_time = captured_time
			if current_time < captured_time :
				current_time = captured_time
				f = open("timestamp", "w")
				f.write((str(timestamp)))
				f.close()
				#print("Captured: ", captured_time)
				#print("Tiempo mayor") 
				print("Detectada incidencia sobre la IP: ",event["data"]["dest_ip"])
				#ip_attacker = "192.168.43.242"
				if ruleID == "100004":
					ip_victim = event["data"]["dest_ip"]
					ip_attacker = event["data"]["src_ip"]					
					command_linux = "sshpass -f password ssh -o StrictHostKeyChecking=no root@"+ip_victim+ " iptables -A INPUT -s "+ip_attacker+" -j DROP"
					name_rule_win = "BLOCK_IP_"+ip_attacker
					command_windows = "netsh advfirewall firewall add rule name="+name_rule_win+" dir=in action=block remoteip="+ip_attacker
				elif ruleID == "100006":
					ip_victim = event["data"]["src_ip"]
					ip_attacker = event["data"]["dest_ip"]
					command_linux = "sshpass -f password ssh -o StrictHostKeyChecking=no root@"+ip_victim+ " iptables -A INPUT -s "+ip_attacker+" -j DROP"
					name_rule_win = "BLOCK_IP_"+ip_attacker
					command_windows = "netsh advfirewall firewall add rule name="+name_rule_win+" dir=in action=block remoteip="+ip_attacker
				elif ruleID == "100007":
					ip_victim = event["data"]["src_ip"]
					ip_attacker = event["data"]["dest_ip"]
					command_linux="sshpass -f password ssh -o StrictHostKeyChecking=no root@"+ip_victim+ " iptables -A INPUT -s "+ip_attacker+" -j DROP; echo 1 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a && printf '\n%s\n' 'Caché de RAM y Swap liberadas'"						
					name_rule_win = "BLOCK_IP_"+ip_attacker
					command_windows = "netsh advfirewall firewall add rule name="+name_rule_win+" dir=in action=block remoteip="+ip_attacker
				elif ruleID == "100008":
					ip_victim = event["data"]["dest_ip"]
					ip_attacker = event["data"]["src_ip"]
					command_linux="sshpass -f password ssh -o StrictHostKeyChecking=no root@"+ip_victim+ " iptables -A INPUT -s "+ip_attacker+" -j DROP; echo 1 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a && printf '\n%s\n' 'Caché de RAM y Swap liberadas'"						
				#command = "sshpass -f password ssh root@"+ip_victim+ " iptables -A INPUT -s "+ip_attacker+" -j DROP"
				#pdb.set_trace()
					name_rule_win = "BLOCK_IP_"+ip_attacker
					command_windows = "netsh advfirewall firewall add rule name="+name_rule_win+" dir=in action=block remoteip="+ip_attacker
				#print("agentes", agentList)
				for agent in agentList:
					#print ("agente: ", agent["ip"])
					if ip_victim == agent["ip"]:				
						#print("Command: ", command_linux)
						#pdb.set_trace()
						if IGNORE == False:
							if agent['SO'] == "Linux":
								p = subprocess.Popen(command_linux, stdout=subprocess.PIPE, shell=True)
								command = command_linux
							elif agent['SO'] == "Windows":
								p = subprocess.Popen(command_windows, stdout=subprocess.PIPE, shell=True)
								command = command_windows
							print(p.communicate())
							f_write = io.open('command_log', mode="a", encoding="latin-1")
							f_write.write(command)
							f_write.close()
							f_write = io.open('firewall_windows_rules', mode="a", encoding="latin-1")
							f_write.write(name_rule_win)
