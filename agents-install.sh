


                                ************ SSM-AGENT**************


dnf install https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm

systemctl enable amazon-ssm-agent 	

systemctl start amazon-ssm-agent







                                ****************CW-AGiENT*************



yum install collectd -y

wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm

rpm -Uvf amazon-cloudwatch-agent.rpm

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-config-wizard

systemctl enable amazon-cloudwatch-agent.service

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json

systemctl restart amazon-cloudwatch-agent.service

systemctl status amazon-cloudwatch-agent.service






                                ****************WAZUH/SIEM-AGENT**************





curl -o wazuh-agent-4.7.0-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.aarch64.rpm



systemctl daemon-reload
WAZUH_MANAGER='65.2.59.252' WAZUH_AGENT_GROUP='AWS_NON_PROD' rpm -ihv wazuh-agent-4.7.0-1.aarch64.rpmsystemctl enable wazuh-agent
systemctl start wazuh-agent







                                    ***************SOPHOS-AGENT****************



wget  https://api-cloudstation-us-east-2.prod.hydra.sophos.com/api/download/0d1ab8ccf35da7d2a2f56265ff5fbb96/SophosSetup.sh

mount -t tmpfs -o exec tmpfs /tmp

chmod +x sophosSetup.sh
run the script











