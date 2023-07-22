#!/bin/bash
# This script automates the server configuration with specific network settings, software installation, firewall rules, and user creation.

# Function to set the hostname to 'autosrv' if it's not already set
set_hostname() {
    local desired_hostname="autosrv"
    if [ "$(hostname)" != "$desired_hostname" ]; then
        hostnamectl set-hostname "$desired_hostname"
        echo "Hostname set to $desired_hostname"
    else
        echo "Hostname is already set to $desired_hostname"
    fi
}

# Function to set up the network interface with specific configurations
setup_network() {
    local IP_ADDR="192.168.16.21/24"
    local GATEWAY="192.168.16.1"
    local DNS_DOMAINS="home.arpa localdomain"
    local INTERFACE="$(ip route | awk '$1 == "default" {default_route = $3} $3 != default_route {print $3}')"

    if [ -n "$INTERFACE" ]; then
        ip addr add "$IP_ADDR" dev "$INTERFACE"
        ip route add default via "$GATEWAY" dev "$INTERFACE"
        echo "search $DNS_DOMAINS" >> /etc/resolv.conf
        ip link set "$INTERFACE" up
        echo "Network interface $INTERFACE configured with IP $IP_ADDR"
    else
        echo "Error: Unable to detect network interface. Network configuration skipped."
    fi
}

# Function to install required software packages
install_software() {
    local required_packages=("openssh-server" "apache2" "squid")
    local installed_packages=()
    for package in "${required_packages[@]}"; do
        if ! dpkg -l "$package" &>/dev/null; then
            apt-get install -y "$package"
            installed_packages+=("$package")
        fi
    done
    if [ ${#installed_packages[@]} -gt 0 ]; then
        echo "Installed software: ${installed_packages[*]}"
    else
        echo "All required software already installed."
    fi
}

# Function to configure SSH for better security
configure_ssh() {
    if grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config; then
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
        systemctl restart sshd
        echo "SSH password authentication disabled."
    else
        echo "SSH password authentication is already disabled."
    fi
}

# Function to configure the firewall rules
configure_firewall() {
    local allowed_ports=("22/tcp" "80/tcp" "443/tcp" "3128/tcp")
    for port in "${allowed_ports[@]}"; do
        if ! ufw status | grep -q "$port"; then
            ufw allow "$port"
        fi
    done
    ufw --force enable
    echo "Firewall configured and enabled."
}

# Main function that executes all the setup functions
main() {
    set_hostname
    setup_network
    install_software
    configure_ssh
    configure_firewall
}

# Run the main function with superuser privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run the script with superuser (root) privileges."
    exit 1
else
    main "$@"
fi

# User creation and SSH key setup
USERS=("dennis" "aubrey" "captain" "nibbles" "brownie" "scooter" "sandy" "perrier" "cindy" "tiger" "yoda")

# Loop through each user in the USERS array and perform necessary setup
for USER in "${USERS[@]}"; do
    if ! id "$USER" &>/dev/null; then
        useradd -m -s /bin/bash "$USER"
        mkdir -p "/home/$USER/.ssh"
        ssh-keygen -t rsa -f "/home/$USER/.ssh/id_rsa" -q -N ""
        ssh-keygen -t ed25519 -f "/home/$USER/.ssh/id_ed25519" -q -N ""
        cat "/home/$USER/.ssh/id_rsa.pub" >> "/home/$USER/.ssh/authorized_keys"
        cat "/home/$USER/.ssh/id_ed25519.pub" >> "/home/$USER/.ssh/authorized_keys"
        chmod 700 "/home/$USER/.ssh"
        chmod 600 "/home/$USER/.ssh/id_rsa"
        chmod 600 "/home/$USER/.ssh/id_ed25519"
        chmod 644 "/home/$USER/.ssh/authorized_keys"
        echo "User $USER created with SSH keys."
    else
        echo "User $USER already exists. Skipping user creation."
    fi
done

# Add sudo access and extra public key to the 'dennis' user
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm' >> /home/dennis/.ssh/authorized_keys
usermod -aG sudo dennis
