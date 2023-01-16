#!/bin/bash.
for source in $(ls | grep rules | sed -r 's/.rules//g')

	do
		echo $source.rules
		suricata-update remove-source $source	
		suricata-update
		suricata-update add-source $source file:///root/Instalacion_Local/rules/$source.rules
	done		
suricata-update	
	
