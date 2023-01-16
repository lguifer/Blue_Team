import io
import json, pdb, subprocess, time, os
from datetime import datetime
MI_IP = "192.168.43.240" #Actualizar este valor a la IP desde donde se lanza este script
machineList = []
def createDir (ruta):	
	if os.path.exists(ruta) == False:
		command = "mkdir "+ruta
		p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
		print(p.communicate())	

def generateRepository():
	current_path = cwd = os.getcwd()
	#createDir(current_path+"/Blue-Teamers")
	#current_path = current_path + "/Blue-Teamers"
	try:

		f_agents = io.open('machines.json', mode="r", encoding="latin-1")

		for jsonObj in f_agents:
			eventDict = json.loads(jsonObj)
			machineList.append(eventDict)
		f_agents.close()		
	except:
		print("Error leyendo archivo JSON: ")
		time.sleep(0.1)
		exit()
	for machine in machineList:
		ip = machine["ip"]
		so = machine["SO"]
		name = machine["name"]
		if name == "wazuh":	
			createDir(current_path+"/wazuh")
			command = "sshpass -f password scp -r root@"+ip+":/root/wazuh "+current_path+"/wazuh/"
			#pdb.set_trace()			
			p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
			print(p.communicate())
			command = "sshpass -f password scp root@"+ip+":/var/ossec/etc/rules/local_rules.xml " +current_path+"/wazuh/"
			p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
			print(p.communicate())
			command = "sshpass -f password scp root@"+ip+":/var/ossec/etc/ossec.conf "+current_path+"/wazuh/"
			p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
			print(p)
		elif name == "suricata":
			createDir(current_path+"/"+name)
			command = "sshpass -f password scp -r root@"+ip+":/root/Instalacion_Local/rules/ "+current_path+"/suricata/"
			p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
			print(p.communicate())

if __name__ == '__main__':
	generateRepository()

