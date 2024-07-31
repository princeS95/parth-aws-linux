#sudo bash -c 'cat << "EOF" > /root/update_java_home.sh
!/bin/bash
 
JAVA_PATH="/usr/lib/jvm"
 
# Function to get existing JAVA_HOME from /etc/environment
get_existing_java_home() {
    grep "^JAVA_HOME=" /etc/environment | grep -v "^#" | tail -n 1 | cut -d"=" -f2
}
 
# Get existing JAVA_HOME from /etc/environment
EXISTING_JAVA_HOME=$(get_existing_java_home)
 
# Find the latest Java version installed
JAVA_VERSION=$(ls -1 ${JAVA_PATH} | grep "^java-1\.8\." | sort -V | tail -n 1)
 
# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')
 
if [ -n "${JAVA_VERSION}" ]; then
    # Set JAVA_HOME in /etc/environment
    sudo sed -i "s|^JAVA_HOME=.*$|JAVA_HOME=${JAVA_PATH}/${JAVA_VERSION}|" /etc/environment
 
    # Reload /etc/environment to apply changes for the current shell
    export JAVA_HOME=$(grep "^JAVA_HOME=" /etc/environment | cut -d"=" -f2)
 
    # Print existing and updated JAVA_HOME for verification
    echo "Existing JAVA_HOME: ${EXISTING_JAVA_HOME}"
    echo "Updated JAVA_HOME: ${JAVA_PATH}/${JAVA_VERSION}"
 
    # Prepare email body with existing and updated JAVA_HOME and server IP
    EMAIL_BODY="Server IP: ${SERVER_IP}\nExisting JAVA_HOME: ${EXISTING_JAVA_HOME}\nUpdated JAVA_HOME: ${JAVA_PATH}/${JAVA_VERSION}"
 
    # Send notification email
    echo -e "${EMAIL_BODY}" | mailx \
        -s "${SERVER_IP} : Server Packages Updated" \
        -S smtp-use-starttls \
        -S ssl-verify=ignore \
        -S smtp-auth=login \
        -S smtp=smtp://smtp-mail.outlook.com:587 \
        -S from="issue@onlinepsbloans.com" \
        -S smtp-auth-user="issue@onlinepsbloans.com" \
        -S smtp-auth-password="Password@123" \
        -S nss-config-dir=/etc/pki/nssdb/ \
        infra@onlinepsbloans.com
 
    echo "Notification email sent"
else
    echo "No Java 1.8 installation found in ${JAVA_PATH}"
fi
#EOF'
 
# Make the script executable
#sudo chmod +x /root/update_java_home.sh
 
# Add cron job for 8:30 PM every day directly to /etc/crontab
#echo "30 20 * * * root /root/update_java_home.sh" | sudo tee -a /etc/crontabsudo bash -c 'cat << "EOF" > /root/update_java_home.sh