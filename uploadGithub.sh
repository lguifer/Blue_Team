echo "# Blue_Team" >> README.md
git init
git add README.md
git commit -m "Se han añadido reglas de firewall y mejorado el código de la respuesta activa de Wazuh."
git branch -M main
#git remote add origin https://github.com/lguifer/Blue_Team.git
git push -u origin main
