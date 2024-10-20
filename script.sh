#!/bin/bash

# Codes de couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Vérifier si l'utilisateur est root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Ce script doit être exécuté en tant que root.${NC}"
    exit 1
fi

print_space_line() {
    echo -e "${MAGENTA}----------------------------------------------------------------${NC}"
    echo -e "${MAGENTA}----------------------------------------------------------------${NC}"
}

# afficher une legende pour l'utilisateur
print_space_line
echo -e "${BLUE}LEGENDE:${NC}"
echo -e "${GREEN}Les commandes qui réussissent.${NC}"
echo -e "${BLUE}Les commandes peuvent${NC} nécessiter une attention, sans être une erreur fatale.${NC}"
echo -e "${RED}Les commandes qui échouent.${NC}"
echo -e "${BLUE}Des informations supplémentaires ou de progression.${NC}"
print_space_line

# Demander les mots de passe et la clé SSH à l'utilisateur
print_space_line
echo -e "${BLUE}Veuillez entrer les mots de passe pour les utilisateurs.${NC}"
read -sp "Mot de passe pour 'user': " user_password
echo
read -sp "Mot de passe pour 'admin': " admin_password
echo
read -sp "Mot de passe pour 'root': " root_password
echo
read -sp "Mot de passe pour 'proxmox-admin': " proxmox_admin_password
echo
read -sp "Mot de passe pour 'proxmox-reader': " proxmox_reader_password
echo
read -sp "Clé SSH pour l'utilisateur 'user': " ssh_key_user
echo
read -sp "Discord Webhook URL: " discord_webhook_url
echo
echo -e "${GREEN}Configuration terminée. Le script est maintenant autonomme.${NC}"
print_space_line

send_discord_notification() {
    local message_content=$1
    local discord_webhook_url=$discord_webhook_url

    # JSON correct pour envoyer à Discord
    local json_payload=$(jq -n --arg content "$message_content" '{content: $content}')

    # Envoi de la requête HTTP à Discord
    curl -H "Content-Type: application/json" -d "$json_payload" "$discord_webhook_url"
}

# Fonction pour vérifier si une commande échoue et envoyer un message à Discord
check_command() {
    if [ $? -ne 0 ]; then
        local error_message="Erreur lors de l'exécution de la commande : '$BASH_COMMAND' sur $(hostname)."
        echo -e "${RED}$error_message${NC}"
        
        # Optionnel : Récupérer les 10 dernières commandes de l'historique
        local recent_history=$(history | tail -n 10)
        local detailed_message="$error_message\nHistorique des dernières commandes :\n$recent_history"
        
        echo -e "${RED}$detailed_message${NC}"

        # Appel à la fonction pour envoyer la notification à Discord
        send_discord_notification "$detailed_message"
        
        exit 1
    fi
}

# Mettre à jour le système
print_space_line
echo -e "${BLUE}Mise à jour du système et installation des dependances...${NC}"
sudo apt-get update -y && check_command
sudo apt install net-tools jq fail2ban iptables-persistent rsyslog -y && check_command
sudo systemctl enable netfilter-persistent && check_command
sudo systemctl enable fail2ban && check_command
sudo systemctl enable rsyslog && check_command
sudo apt-get upgrade -y && check_command
sudo apt-get autoremove -y && check_command
echo -e "${GREEN}Système mis à jour avec succès.${NC}"
print_space_line

# Vérifier si un utilisateur existe déjà avant de le créer
create_user_if_not_exists() {
    local username=$1
    if id "$username" &>/dev/null; then
        echo -e "${YELLOW}L'utilisateur $username existe déjà${NC}"
    else
        sudo useradd -m -s /bin/bash "$username" && check_command
        echo -e "${GREEN}Utilisateur $username créé avec succès${NC}"
    fi
}

create_proxmox_user_if_not_exists() {
    local username=$1
    if sudo pveum user list | grep -q "$username@pve"; then
        echo -e "${YELLOW}L'utilisateur $username@pve existe déjà${NC}"
    else> /dev/null 
        sudo pveum useradd "$username@pve" -comment "$username" && check_command
        echo -e "${GREEN}Utilisateur $username@pve créé avec succès${NC}"
    fi
}

# Créer les utilisateurs PAM : user, admin
print_space_line
echo -e "${BLUE}Création des utilisateurs PAM...${NC}"
create_user_if_not_exists "user" 
create_user_if_not_exists "admin"
echo -e "${GREEN}Utilisateurs PAM créés avec succès.${NC}"
print_space_line

# Créer les utilisateurs Proxmox : proxmox-admin et proxmox-reader
print_space_line
echo -e "${BLUE}Création des utilisateurs PVE...${NC}"
create_proxmox_user_if_not_exists "proxmox-admin"
create_proxmox_user_if_not_exists "proxmox-reader"
sleep 3
echo -e "${GREEN}Utilisateurs PVE créés avec succès.${NC}"
print_space_line

# Définir des mots de passe par défaut pour chaque utilisateur
print_space_line
echo -e "${BLUE}Définition des mots de passe pour les utilisateurs PAM...${NC}"
echo "user:$user_password" | sudo chpasswd && check_command
echo "admin:$admin_password" | sudo chpasswd && check_command
echo "root:$root_password" | sudo chpasswd && check_command
echo -e "${GREEN}Mots de passe définis avec succès.${NC}"
print_space_line

# Ajouter les utilisateurs PAM aux groupes appropriés
print_space_line
echo -e "${BLUE}Ajout des utilisateurs aux groupes appropriés...${NC}"
sudo usermod -aG sudo admin && check_command
echo -e "${GREEN}Utilisateurs ajoutés aux groupes avec succès.${NC}"
print_space_line

# Définir des mots de passe pour les utilisateurs Proxmox
print_space_line
echo -e "${BLUE}Définition des mots de passe pour les utilisateurs PVE...${NC}"
echo -e "$proxmox_admin_password\n$proxmox_admin_password" | sudo pveum passwd proxmox-admin@pve && check_command
echo -e "$proxmox_reader_password\n$proxmox_reader_password" | sudo pveum passwd proxmox-reader@pve && check_command
echo -e "${GREEN}Mots de passe définis avec succès.${NC}"
print_space_line

# Attribution des permissions spécifiques
print_space_line
echo -e "${BLUE}Attribution des rôles aux utilisateurs PVE...${NC}"
sudo pveum aclmod / -user proxmox-admin@pve -role PVEAdmin && check_command
sudo pveum aclmod / -user proxmox-reader@pve -role PVEAuditor && check_command
echo -e "${GREEN}Rôles attribués avec succès.${NC}"
print_space_line

# Insérer une clé SSH publique directement dans le fichier authorized_keys de 'user'
print_space_line
echo -e "${BLUE}Ajout de la clé publique dans le fichier authorized_keys de l'utilisateur 'user'...${NC}"
sudo mkdir -p /home/user/.ssh && check_command
sudo chmod 700 /home/user/.ssh && check_command
echo "$ssh_key_user" | sudo tee /home/user/.ssh/authorized_keys > /dev/null && check_command
sudo chmod 600 /home/user/.ssh/authorized_keys && check_command
sudo chown -R user:user /home/user/.ssh && check_command
echo -e "${GREEN}Clé publique ajoutée avec succès.${NC}"
print_space_line

# Retirer les droits sudo à l'utilisateur 'user'
print_space_line
echo -e "${BLUE}Retrait des droits sudo de 'user'...${NC}"
if groups user | grep -q "\bsudo\b"; then
    # Si l'utilisateur 'user' fait partie du groupe sudo, on le retire
    sudo deluser user sudo &&     check_command
else
    # Si l'utilisateur 'user' n'a pas les droits sudo, afficher un message
    echo -e "${YELLOW}L'utilisateur 'user' n'a pas de droits sudo, aucune action nécessaire.${NC}"
fi
print_space_line

# Ecrire la configuration ssh
print_space_line
echo -e "${BLUE}Configuration du service SSH...${NC}"
# Supprimer le fichier sshd_config s'il existe
sudo rm -f /etc/ssh/sshd_config && check_command
# Créer un nouveau fichier sshd_config
sudo touch /etc/ssh/sshd_config && check_command
# Ajouter les configurations au fichier sshd_config
echo "Include /etc/ssh/sshd_config.d/*.conf" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configurer le port ssh
echo "Port 6785" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configurer le SysLogFacility
echo "SysLogFacility AUTH" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configurer le loglevel
echo "LogLevel VERBOSE" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configurer le login grace time
echo "LoginGraceTime 20s" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configurer le nombre de tentatives d'authentification
echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configurer le nombre de sessions
echo "MaxSessions 2" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configurer l'authentification par clé publique
echo "PubkeyAuthentication yes" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Désactiver l'authentification par mot de passe
echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Désactiver les mots de passe vides
echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Désactiver l'authentification interactive
echo "KbdInteractiveAuthentication no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Activer PAM
echo "UsePAM yes" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Activer X11Forwarding
echo "X11Forwarding yes" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Désactiver le message de bienvenue
echo "PrintMotd no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Accepter les variables d'environnement
echo "AcceptEnv LANG LC_*" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Configurer le sous-système sftp
echo "Subsystem       sftp    /usr/lib/openssh/sftp-server" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Désactiver la connexion root
echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Autoriser uniquement l'utilisateur 'user' à se connecter
echo "AllowUsers user" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
# Bloquer les utilisateurs 'admin' et 'root' et afficher un message personnalisé
echo "Match User admin,root" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
echo "  PermitTTY no" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
echo "  ForceCommand echo 'Get the fuck out of here!'" | sudo tee -a /etc/ssh/sshd_config > /dev/null && check_command
echo -e "${GREEN}Configuration du service ssh terminé.${NC}"
print_space_line

# Configuration Iptables
print_space_line
echo -e "${BLUE}Configuration de Iptables${NC}"
echo -e "${BLUE}Les règles seront appliquées au redémarrage du système.${NC}"
# Supprimer le fichier rules.v4 si il existe
iptables_rules_file="/etc/iptables/rules.v4"
sudo rm $iptables_rules_file
# Créer un fichier temporaire pour les règles iptables
touch $iptables_rules_file
echo "*filter" > $iptables_rules_file
# Interdire tout le trafic par défaut
echo "-P INPUT DROP" >> $iptables_rules_file
echo "-P FORWARD DROP" >> $iptables_rules_file
echo "-P OUTPUT DROP" >> $iptables_rules_file
# Autoriser le trafic local
echo "-A INPUT -i lo -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -o lo -j ACCEPT" >> $iptables_rules_file
# Autoriser le trafic SSH sur le port 6785
echo "-A INPUT -p tcp --dport 6785 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --sport 6785 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
# Autoriser le trafic HTTP/HTTPS
echo "-A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
# Autoriser le trafic DNS
echo "-A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT" >> $iptables_rules_file
# Autoriser le trafic ICMP
echo "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT" >> $iptables_rules_file
echo "-A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT" >> $iptables_rules_file
echo "-A INPUT -p icmp --icmp-type echo-reply -j ACCEPT" >> $iptables_rules_file
# Autoriser les nouvelles connexions entrantes sur le port 8006 (Proxmox Web)
echo "-A INPUT -p tcp --dport 8006 -m conntrack --ctstate NEW -j ACCEPT" >> $iptables_rules_file
# Ajouter des logs pour les paquets rejetés
echo "-A INPUT -j LOG --log-prefix \"Paquet INPUT rejeté: \" --log-level 4" >> $iptables_rules_file
echo "-A OUTPUT -j LOG --log-prefix \"Paquet OUTPUT rejeté: \" --log-level 4" >> $iptables_rules_file
# Ajouter des logs pour les paquets acceptés
### SSH
echo "-A INPUT -p tcp --dport 6785 -m conntrack --ctstate NEW,ESTABLISHED -j LOG --log-prefix \"Input port 6785 acceptée: \" --log-level 4" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --sport 6785 -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix \"Output port 6785 envoyée: \" --log-level 4" >> $iptables_rules_file
### HTTP/HTTPS
echo "-A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix \"Inout port 80 reçue: \" --log-level 4" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j LOG --log-prefix \"Output port 80 envoyée: \" --log-level 4" >> $iptables_rules_file
echo "-A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix \"Input port 443 reçue: \" --log-level 4" >> $iptables_rules_file
echo "-A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j LOG --log-prefix \"Output port 443 envoyée: \" --log-level 4" >> $iptables_rules_file
# Terminer le fichier de règles
echo "COMMIT" >> $iptables_rules_file
echo -e "${GREEN}Les règles iptables ont été enregistrées dans $iptables_rules_file mais ne seront appliquées qu'au redémarrage.${NC}"
print_space_line

# Configurer Fail2Ban
print_space_line
echo -e "${BLUE}Configuration de Fail2Ban...${NC}"
# Supprimer le fichier jail.local s'il existe
sudo rm -f /etc/fail2ban/jail.local && check_command
# Créer un nouveau fichier jail.local
sudo touch /etc/fail2ban/jail.local && check_command
# Définir les configurations DEFAULT
echo "[DEFAULT]" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le temps de bannissement
echo "bantime = 1h" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le nombre de tentatives échouées avant le bannissement
echo "maxretry = 3" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir la fenêtre de temps pendant laquelle les tentatives échouées doivent se produire
echo "findtime = 10m" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir l'IP à ignorer (localhost)
echo "ignoreip = 127.0.0.1/8 ::1" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir l'action de bannissement
echo "banaction = iptables-multiport" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir la cible de log
echo "logtarget = /var/log/fail2ban.log" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le niveau de log
echo "loglevel = DEBUG" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir les configurations pour SSH
echo "# --- Protection pour SSH ---" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
echo "[sshd]" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Activer la protection pour SSH
echo "enabled = true" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le port SSH
echo "port = 6785" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le chemin du log auth.log
echo "logpath = /var/log/auth.log" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le nombre de tentatives échouées avant le bannissement
echo "maxretry = 3" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le temps de bannissement
echo "bantime = 1h" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir la fenêtre de temps pendant laquelle les tentatives échouées doivent se produire
echo "findtime = 10m" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir les configurations pour Proxmox
echo "# --- Protection pour Proxmox ---" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
echo "[proxmox]" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Activer la protection pour Proxmox
echo "enabled = true" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le port Proxmox
echo "port = http,https,8006" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le filtre
echo "filter = proxmox" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le type de backend
echo "backend = systemd" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le chemin du log access.log
echo "logpath = /var/log/pveproxy/access.log" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le nombre de tentatives échouées avant le bannissement
echo "maxretry = 3" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir le temps de bannissement
echo "bantime = 1h" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Définir la fenêtre de temps pendant laquelle les tentatives échouées doivent se produire
echo "findtime = 10m" | sudo tee -a /etc/fail2ban/jail.local  > /dev/null && check_command
# Supprimer le fichier de filtre pour Proxmox s'il existe
sudo rm -f /etc/fail2ban/filter.d/proxmox.conf && check_command
# Créer le fichier de filtre pour Proxmox
sudo touch /etc/fail2ban/filter.d/proxmox.conf && check_command
# Ajouter les configurations au fichier de filtre pour Proxmox
echo "[Definition]" | sudo tee -a /etc/fail2ban/filter.d/proxmox.conf  > /dev/null && check_command
# Définir failregex pour Proxmox
echo "failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*" | sudo tee -a /etc/fail2ban/filter.d/proxmox.conf  > /dev/null && check_command
# Définir ignoreregex pour Proxmox
echo "ignoreregex =" | sudo tee -a /etc/fail2ban/filter.d/proxmox.conf  > /dev/null && check_command
# Définir le journalmatch pour Proxmox
echo "journalmatch = _SYSTEMD_UNIT=pveproxy.service" | sudo tee -a /etc/fail2ban/filter.d/proxmox.conf  > /dev/null && check_command

echo -e "${GREEN}Configuration de Fail2Ban terminée.${NC}"
print_space_line

# Configuration de logrotate
print_space_line
echo -e "${BLUE}Configuration de logrotate...${NC}"
# Supprimer le fichier fail2ban s'il existe
sudo rm -f /etc/logrotate.d/fail2ban && check_command
# Créer un nouveau fichier fail2ban
sudo touch /etc/logrotate.d/fail2ban && check_command
# Ajouter les configurations au fichier fail2ban
echo "/var/log/fail2ban.log {" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Configurer la rotation des logs
echo "    daily" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo "    rotate 7" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Activer la compression
echo "    compress" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Ignorer les fichiers manquants
echo "    missingok" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Ignorer les fichiers vides
echo "    notifempty" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Délai de compression
echo "    delaycompress" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Créer le fichier avec les permissions 640
echo "    create 640 root adm" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
# Exécuter la commande fail2ban-client flushlogs
echo "    postrotate" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo "        /usr/bin/fail2ban-client flushlogs >/dev/null || true" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo "    endscript" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo "}" | sudo tee -a /etc/logrotate.d/fail2ban > /dev/null && check_command
echo -e "${GREEN}Configuration de logrotate terminée.${NC}"
print_space_line

print_space_line
echo -e "${GREEN}Configuration terminée.${NC}"
print_space_line

# Envoyer une notification Discord pour informer de la fin de la configuration
send_discord_notification "Configuration terminée avec succès sur $(hostname). Redémarrage du serveur..."

# echo pour créditer l'auteur du script
print_space_line
echo -e "${BLUE}Script réalisé par @Vincent6785${NC}"
print_space_line
# Redémarrer le serveur après 10 secondes
print_space_line
echo -e "${BLUE}Redémarrage du serveur dans 10 secondes...${NC}"
sleep 10
#sudo reboot