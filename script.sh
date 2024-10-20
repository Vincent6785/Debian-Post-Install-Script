#!/bin/bash

# colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# check if the script is running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}This script must be executed as root.${NC}"
    exit 1
fi

print_space_line() {
    echo -e "${MAGENTA}----------------------------------------------------------------${NC}"
    echo -e "${MAGENTA}----------------------------------------------------------------${NC}"
}

# Display a legend for the user
print_space_line
echo -e "${BLUE}LEGEND:${NC}"
echo -e "${GREEN}Commands that succeed.${NC}"
echo -e "${BLUE}Commands may require attention, without being a fatal error.${NC}"
echo -e "${RED}Commands that fail.${NC}"
echo -e "${BLUE}Additional or progress information.${NC}"

# Prompt the user for passwords and the SSH key
print_space_line
echo -e "${BLUE}Please enter the passwords for the users.${NC}"
read -sp "Password for 'user': " user_password
echo
read -sp "Password for 'admin': " admin_password
echo
read -sp "Password for 'root': " root_password
echo
read -sp "Password for 'proxmox-admin': " proxmox_admin_password
echo
read -sp "Password for 'proxmox-reader': " proxmox_reader_password
echo
read -sp "SSH key for 'user': " ssh_key_user
echo
read -sp "Discord Webhook URL: " discord_webhook_url
echo
echo -e "${GREEN}Configuration complete. The script is now autonomous.${NC}"

send_discord_notification() {
    local message_content=$1
    local discord_webhook_url=$discord_webhook_url

    # Proper JSON to send to Discord
    local json_payload=$(jq -n --arg content "$message_content" '{content: $content}')

    # Send the HTTP request to Discord
    curl -H "Content-Type: application/json" -d "$json_payload" "$discord_webhook_url"
}

# Function to check if a command fails and send a message to Discord
check_command() {
    if [ $? -ne 0 ]; then
        local error_message="Error while executing the command: '$BASH_COMMAND' on $(hostname)."
        echo -e "${RED}$error_message${NC}"
        
        # Optional: Retrieve the last 10 commands from the history
        local recent_history=$(history | tail -n 10)
        local detailed_message="$error_message\nHistory of recent commands:\n$recent_history"
        
        echo -e "${RED}$detailed_message${NC}"

        # Call the function to send the notification to Discord
        send_discord_notification "$detailed_message"
        
        exit 1
    fi
}

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

# Check if a user already exists before creating them
create_user_if_not_exists() {
    local username=$1
    if id "$username" &>/dev/null; then
        echo -e "${YELLOW}User $username already exists${NC}"
    else
        sudo useradd -m -s /bin/bash "$username" && check_command
        echo -e "${GREEN}User $username created successfully${NC}"
    fi
}

create_proxmox_user_if_not_exists() {
    local username=$1
    if sudo pveum user list | grep -q "$username@pve"; then
        echo -e "${YELLOW}The user $username@pve already exists${NC}"
    else > /dev/null
        sudo pveum useradd "$username@pve" -comment "$username" && check_command
        echo -e "${GREEN}User $username@pve created successfully${NC}"
    fi
}

# Create PAM users: user, admin
print_space_line
echo -e "${BLUE}Creating PAM users...${NC}"
create_user_if_not_exists "user" 
create_user_if_not_exists "admin"
echo -e "${GREEN}PAM users created successfully.${NC}"

# Create Proxmox users: proxmox-admin and proxmox-reader
print_space_line
echo -e "${BLUE}Creating PVE users...${NC}"
create_proxmox_user_if_not_exists "proxmox-admin"
create_proxmox_user_if_not_exists "proxmox-reader"
sleep 3
echo -e "${GREEN}PVE users created successfully.${NC}"

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

# Set passwords for Proxmox users
print_space_line
echo -e "${BLUE}Setting passwords for PVE users...${NC}"
echo -e "$proxmox_admin_password\n$proxmox_admin_password" | sudo pveum passwd proxmox-admin@pve && check_command
echo -e "$proxmox_reader_password\n$proxmox_reader_password" | sudo pveum passwd proxmox-reader@pve && check_command
echo -e "${GREEN}Passwords set successfully.${NC}"

# Assign specific permissions
print_space_line
echo -e "${BLUE}Assigning roles to PVE users...${NC}"
sudo pveum aclmod / -user proxmox-admin@pve -role PVEAdmin && check_command
sudo pveum aclmod / -user proxmox-reader@pve -role PVEAuditor && check_command
echo -e "${GREEN}Roles assigned successfully.${NC}"

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
echo -e "${BLUE}The rules will be applied on system reboot.${NC}"
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
# Allow traffic on port 8006 (Proxmox Web)
echo "-A INPUT -p tcp --dport 8006 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --sport 8006 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
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
echo -e "${GREEN}Iptables rules have been saved in $iptables_rules_file but will only be applied on reboot.${NC}"

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
# Set configurations for Proxmox
echo "# --- Protection for Proxmox ---" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
echo "[proxmox]" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Enable Proxmox protection
echo "enabled = true" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the Proxmox port
echo "port = http,https,8006" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the filter
echo "filter = proxmox" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the backend type
echo "backend = systemd" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the path to the access.log file
echo "logpath = /var/log/pveproxy/access.log" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the max number of failed attempts before a ban
echo "maxretry = 3" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the ban time
echo "bantime = 1h" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Set the time window for failed attempts
echo "findtime = 10m" | sudo tee -a /etc/fail2ban/jail.local > /dev/null && check_command
# Remove the Proxmox filter file if it exists
sudo rm -f /etc/fail2ban/filter.d/proxmox.conf && check_command
# Create the Proxmox filter file
sudo touch /etc/fail2ban/filter.d/proxmox.conf && check_command
# Add configurations to the Proxmox filter file
echo "[Definition]" | sudo tee -a /etc/fail2ban/filter.d/proxmox.conf > /dev/null && check_command
# Set the failregex for Proxmox
echo "failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*" | sudo tee -a /etc/fail2ban/filter.d/proxmox.conf > /dev/null && check_command
# Set the ignoreregex for Proxmox
echo "ignoreregex =" | sudo tee -a /etc/fail2ban/filter.d/proxmox.conf > /dev/null && check_command
# Set the journalmatch for Proxmox
echo "journalmatch = _SYSTEMD_UNIT=pveproxy.service" | sudo tee -a /etc/fail2ban/filter.d/proxmox.conf > /dev/null && check_command
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

# Send a Discord notification to inform of configuration completion
send_discord_notification "Configuration successfully completed on $(hostname). Restarting the server..."

# Echo to credit the author of the script
print_space_line
echo -e "${BLUE}Script created by @Vincent6785${NC}"

# Restart the server after 10 seconds
print_space_line
echo -e "${BLUE}Restarting the server in 10 seconds...${NC}"
sleep 10
sudo reboot
