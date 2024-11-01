#!/bin/bash

# region variables
# colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'
# endregion variables

# region fonctions
send_discord_notification() {
    local message_content=$1
    local discord_webhook_url=$2

    local json_payload=$(jq -n --arg content "$message_content" '{content: $content}')
    curl -H "Content-Type: application/json" -d "$json_payload" "$discord_webhook_url"
}

check_command() {
    if [ $? -ne 0 ]; then
        local error_message="Error while executing the command: '$BASH_COMMAND' on $(hostname)."
        echo -e "${RED}$error_message${NC}"

        local recent_history=$(history | tail -n 10)
        local detailed_message="$error_message\nHistory of recent commands:\n$recent_history"

        echo -e "${RED}$detailed_message${NC}"
        send_discord_notification "$detailed_message" "$discord_webhook_url"

        exit 1
    fi
}

create_user_if_not_exists() {
    local username=$1
    if id "$username" &>/dev/null; then
        echo -e "${YELLOW}User $username already exists${NC}"
    else
        sudo useradd -m -s /bin/bash "$username" && check_command
        echo -e "${GREEN}User $username created successfully${NC}"
    fi
}

print_space_line() {
    echo -e "${MAGENTA}----------------------------------------------------------------${NC}"
    echo -e "${MAGENTA}----------------------------------------------------------------${NC}"
}
# endregion fonctions

# region main

# check if the script is running as sudo
print_space_line
echo -e "${BLUE}Checking if the script is running as sudo...${NC}"
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Ce script doit être exécuté en tant que sudo.${NC}"
    sudo bash "$0" "$@"

    # exit the current process    
    exit
else
    echo -e "${GREEN}Le script est en cours d'exécution en tant que sudo.${NC}"
fi

# Vérification des variables d'environnement OU demande de saisie
if [ -z "$USER_PASSWORD" ]; then
    print_space_line
    echo -e "${BLUE}Please enter the passwords for the users.${NC}"
    read -sp "Password for 'user': " user_password
    echo
    echo "export USER_PASSWORD='$user_password'" >> ~/.bashrc
    source ~/.bashrc
fi
if [ -z "$ADMIN_PASSWORD" ]; then
    read -sp "Password for 'admin': " admin_password
    echo
    echo "export ADMIN_PASSWORD='$admin_password'" >> ~/.bashrc
    source ~/.bashrc
fi
if [ -z "$ROOT_PASSWORD" ]; then
    read -sp "Password for 'root': " root_password
    echo
    echo "export ROOT_PASSWORD='$root_password'" >> ~/.bashrc
    source ~/.bashrc
fi
if [ -z "$SSH_KEY_USER" ]; then
    read -sp "SSH key for 'user': " ssh_key_user
    echo  
    echo "export SSH_KEY_USER='$ssh_key_user'" >> ~/.bashrc
    source ~/.bashrc
fi
if [ -z "$DISCORD_WEBHOOK_URL" ]; then
    read -sp "Discord Webhook URL: " discord_webhook_url
    echo
    echo "export DISCORD_WEBHOOK_URL='$discord_webhook_url'" >> ~/.bashrc
    source ~/.bashrc
fi

# Exécution du reste du script
print_space_line
echo -e "${BLUE}LEGEND:${NC}"
echo -e "${GREEN}Commands that succeed.${NC}"
echo -e "${YELLOW}Commands may require attention, without being a fatal error.${NC}"
echo -e "${RED}Commands that fail.${NC}"
echo -e "${BLUE}Additional or progress information.${NC}"

print_space_line
echo -e "${GREEN}Configuration complete. The script is now autonomous.${NC}"

# Update the system
print_space_line
echo -e "${BLUE}Updating the system and installing dependencies...${NC}"
sudo apt-get update -y && check_command
sudo apt install net-tools jq fail2ban iptables-persistent rsyslog -y && check_command
sudo systemctl enable netfilter-persistent && check_command
sudo systemctl enable fail2ban && check_command
sudo systemctl enable rsyslog && check_command
sudo apt-get upgrade -y && check_command
sudo apt-get autoremove -y && check_command
echo -e "${GREEN}System successfully updated.${NC}"

# Create PAM users: user, admin
print_space_line
echo -e "${BLUE}Creating PAM users...${NC}"
create_user_if_not_exists "user" 
create_user_if_not_exists "admin"
echo -e "${GREEN}PAM users created successfully.${NC}"

# Set default passwords for each user
print_space_line
echo -e "${BLUE}Setting passwords for PAM users...${NC}"
echo "user:$user_password" | sudo chpasswd && check_command
echo "admin:$admin_password" | sudo chpasswd && check_command
echo "root:$root_password" | sudo chpasswd && check_command
echo -e "${GREEN}Passwords set successfully.${NC}"

# Add PAM users to appropriate groups
print_space_line
echo -e "${BLUE}Adding users to appropriate groups...${NC}"
sudo usermod -aG sudo admin && check_command
echo -e "${GREEN}Users added to groups successfully.${NC}"

# Insert a public SSH key directly into the 'authorized_keys' file of 'user'
print_space_line
echo -e "${BLUE}Adding the public key to the 'authorized_keys' file of the 'user'...${NC}"
sudo mkdir -p /home/user/.ssh && check_command
sudo chmod 700 /home/user/.ssh && check_command
echo "$ssh_key_user" | sudo tee /home/user/.ssh/authorized_keys > /dev/null && check_command
sudo chmod 600 /home/user/.ssh/authorized_keys && check_command
sudo chown -R user:user /home/user/.ssh && check_command
echo -e "${GREEN}Public key added successfully.${NC}"

# Remove sudo rights from the 'user'
print_space_line
echo -e "${BLUE}Removing sudo rights from 'user'...${NC}"
if groups user | grep -q "\bsudo\b"; then
    # If the 'user' is part of the sudo group, remove them
    sudo deluser user sudo && check_command
else
    # If the 'user' does not have sudo rights, display a message
    echo -e "${YELLOW}The 'user' does not have sudo rights, no action needed.${NC}"
fi

# Write the SSH configuration
print_space_line
echo -e "${BLUE}Configuring SSH service...${NC}"
# Remove the sshd_config file if it exists
sudo rm -f /etc/ssh/sshd_config && check_command
# Create a new sshd_config file
sudo touch /etc/ssh/sshd_config && check_command
# Add configurations to the sshd_config file
echo "Include /etc/ssh/sshd_config.d/*.conf" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Set SSH port
echo "Port 6785" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configure SysLogFacility
echo "SysLogFacility AUTH" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Set log level
echo "LogLevel VERBOSE" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Set login grace time
echo "LoginGraceTime 20s" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Set the maximum number of authentication attempts
echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Set the maximum number of sessions
echo "MaxSessions 2" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Enable public key authentication
echo "PubkeyAuthentication yes" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Disable password authentication
echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Disable empty passwords
echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Disable interactive authentication
echo "KbdInteractiveAuthentication no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Enable PAM
echo "UsePAM yes" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Enable X11Forwarding
echo "X11Forwarding yes" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Disable welcome message
echo "PrintMotd no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Accept environment variables
echo "AcceptEnv LANG LC_*" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configure the SFTP subsystem
echo "Subsystem       sftp    /usr/lib/openssh/sftp-server" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Disable root login
echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Allow only 'user' to connect
echo "AllowUsers user" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Block 'admin' and 'root' users and show a custom message
echo "Match User admin,root" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
echo "  PermitTTY no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
echo "  ForceCommand echo 'Get the fuck out of here!'" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
echo -e "${GREEN}SSH service configuration complete.${NC}"

# Iptables Configuration
print_space_line
echo -e "${BLUE}Iptables Configuration${NC}"
# Remove the rules.v4 file if it exists
iptables_rules_file="/etc/iptables/rules.v4"
sudo rm $iptables_rules_file
# Create a temporary file for the iptables rules
touch $iptables_rules_file
echo "*filter" > $iptables_rules_file
# Block all traffic by default
echo "-P INPUT DROP" >> $iptables_rules_file
echo "-P FORWARD DROP" >> $iptables_rules_file
echo "-P OUTPUT DROP" >> $iptables_rules_file
# Allow local traffic
echo "-A INPUT -i lo -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -o lo -j ACCEPT" >> $iptables_rules_file
# Allow SSH traffic on port 6785
echo "-A INPUT -p tcp --dport 6785 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --sport 6785 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
# Allow HTTP/HTTPS traffic
echo "-A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
# Allow DNS traffic
echo "-A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
# Allow ICMP traffic
echo "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p icmp --icmp-type echo-reply -j ACCEPT" >> $iptables_rules_file
# Add logs for dropped packets
echo "-A INPUT -j LOG --log-prefix \"Dropped INPUT packet: \" --log-level 4" >> $iptables_rules_file
echo "-A OUTPUT -j LOG --log-prefix \"Dropped OUTPUT packet: \" --log-level 4" >> $iptables_rules_file
# Add logs for accepted packets
### SSH
echo "-A INPUT -p tcp --dport 6785 -m conntrack --ctstate NEW,ESTABLISHED -j LOG --log-prefix \"Input port 6785 accepted: \" --log-level 4" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --sport 6785 -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix \"Output port 6785 sent: \" --log-level 4" >> $iptables_rules_file
### HTTP/HTTPS
echo "-A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix \"Input port 80 received: \" --log-level 4" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j LOG --log-prefix \"Output port 80 sent: \" --log-level 4" >> $iptables_rules_file
echo "-A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix \"Input port 443 received: \" --log-level 4" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j LOG --log-prefix \"Output port 443 sent: \" --log-level 4" >> $iptables_rules_file
# End the rules file
echo "COMMIT" >> $iptables_rules_file
echo -e "${GREEN}Iptables configuration completed.${NC}"

# Configure Fail2Ban
print_space_line
echo -e "${BLUE}Configuring Fail2Ban...${NC}"
# Remove the jail.local file if it exists
sudo rm -f /etc/fail2ban/jail.local && check_command
# Create a new jail.local file
sudo touch /etc/fail2ban/jail.local && check_command
# Set the DEFAULT configurations
echo "[DEFAULT]" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the ban time
echo "bantime = 1h" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the max number of failed attempts before a ban
echo "maxretry = 3" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the time window for failed attempts
echo "findtime = 10m" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the IP to ignore (localhost)
echo "ignoreip = 127.0.0.1/8 ::1" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the ban action
echo "banaction = iptables-multiport" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the log target
echo "logtarget = /var/log/fail2ban.log" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the log level
echo "loglevel = DEBUG" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set configurations for SSH
echo "# --- Protection for SSH ---" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
echo "[sshd]" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Enable SSH protection
echo "enabled = true" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the SSH port
echo "port = 6785" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the path to the auth.log file
echo "logpath = /var/log/auth.log" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the max number of failed attempts before a ban
echo "maxretry = 3" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the ban time
echo "bantime = 1h" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the time window for failed attempts
echo "findtime = 10m" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
echo -e "${GREEN}Fail2Ban configuration completed.${NC}"

# Logrotate configuration
print_space_line
echo -e "${BLUE}Configuring logrotate...${NC}"
# Remove the fail2ban logrotate file if it exists
sudo rm -f /etc/logrotate.d/fail2ban && check_command
# Create a new fail2ban logrotate file
sudo touch /etc/logrotate.d/fail2ban && check_command
# Add configurations to the fail2ban logrotate file
echo "/var/log/fail2ban.log {" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Set the log rotation schedule
echo "    daily" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo "    rotate 7" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Enable compression
echo "    compress" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Ignore missing files
echo "    missingok" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Ignore empty files
echo "    notifempty" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Delay compression
echo "    delaycompress" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Create the file with 640 permissions
echo "    create 640 root adm" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Run the fail2ban-client flushlogs command
echo "    postrotate" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo "        /usr/bin/fail2ban-client flushlogs >/dev/null || true" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo "    endscript" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo "}" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo -e "${GREEN}Logrotate configuration completed.${NC}"

print_space_line
echo -e "${GREEN}Configuration completed.${NC}"

time=60

# Suppression des variables d'environnement
sed -i '/export USER_PASSWORD=/d' ~/.bashrc
sed -i '/export ADMIN_PASSWORD=/d' ~/.bashrc
sed -i '/export ROOT_PASSWORD=/d' ~/.bashrc
sed -i '/export SSH_KEY_USER=/d' ~/.bashrc
sed -i '/export DISCORD_WEBHOOK_URL=/d' ~/.bashrc
source ~/.bashrc

# Send a Discord notification to inform of configuration completion
send_discord_notification "Configuration successfully completed on $(hostname). Restarting server in $time seconds..." "$discord_webhook_url"

# Echo to credit the author of the script
print_space_line
echo -e "${BLUE}Script created by @Vincent6785${NC}"

# Restart the server after 10 seconds
print_space_line
echo -e "${BLUE}Restarting the server in $time seconds...${NC}"
sleep 60
sudo reboot
# endregion main