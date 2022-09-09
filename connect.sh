chmod 600 fabric_config/bastionD
chmod 600 fabric_config/.ssh/id_rsa
ssh -F ~/work/fabric_config/ssh_config  -i /home/fabric/work/fabric_config/.ssh/id_rsa $1