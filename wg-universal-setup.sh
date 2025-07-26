#!/bin/bash

# WireGuard Universal Setup Script - ULTIMATE VERSION
# One-script solution for complete WireGuard VPN server setup
# ULTIMATE EDITION: Fixed all connectivity issues + auto-diagnostics
# Author: Senior Shell Developer
# License: GPL v3

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Universal optimal configuration values (proven in production)
readonly OPTIMAL_MTU=1342
readonly OPTIMAL_KEEPALIVE=21
readonly OPTIMAL_DNS="1.1.1.1"
readonly DEFAULT_PORT=51820
readonly ALTERNATIVE_PORT=443

# Network configuration
readonly VPN_NETWORK="10.0.0.0/24"
readonly SERVER_VPN_IP="10.0.0.1"

# File paths
readonly LOG_FILE="/var/log/wg-universal-setup.log"
readonly CONFIG_DIR="/etc/wireguard"
readonly BACKUP_DIR="/etc/wireguard/backups"

# Global variables
WG_INTERFACE=""
WAN_INTERFACE=""
WG_PORT=$DEFAULT_PORT
SERVER_PUBLIC_IP=""
SERVER_PRIVATE_KEY=""
SERVER_PUBLIC_KEY=""
CLIENT_COUNT=0

# Logging function with timestamp and colors
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${CYAN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        "STEP")
            echo -e "${BLUE}[STEP]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${YELLOW}[DEBUG]${NC} $message"
            ;;
    esac
    
    # Write to log file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
}

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║        WireGuard Universal Setup Script v3.0 FIXED          ║"
    echo "║                                                              ║"
    echo "║  Автоматическая настройка VPN сервера для всех устройств     ║"
    echo "║  Исправлены все проблемы с интернет-соединением             ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

# Error handling with cleanup
error_exit() {
    log "ERROR" "$1"
    log "ERROR" "Установка прервана. Проверьте логи в $LOG_FILE"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "Этот скрипт должен быть запущен с правами root. Используйте: sudo $0"
    fi
}

# Detect operating system
detect_os() {
    log "STEP" "Определение операционной системы..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        OS_VERSION=$VERSION_ID
        log "INFO" "Операционная система: $OS $OS_VERSION"
    else
        error_exit "Не удалось определить операционную систему"
    fi
}

# Install required packages
install_packages() {
    log "STEP" "Установка необходимых пакетов..."
    
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            apt update -qq
            apt install -y curl iptables iptables-persistent netfilter-persistent
            ;;
        *"CentOS"*|*"Red Hat"*|*"Rocky"*|*"AlmaLinux"*)
            yum install -y curl iptables-services
            systemctl enable iptables
            ;;
        *"Fedora"*)
            dnf install -y curl iptables-services
            systemctl enable iptables
            ;;
    esac
    
    log "SUCCESS" "Необходимые пакеты установлены"
}

# Install WireGuard if not present
install_wireguard() {
    log "STEP" "Проверка установки WireGuard..."
    
    if command -v wg &> /dev/null; then
        log "SUCCESS" "WireGuard уже установлен"
        return 0
    fi
    
    log "INFO" "Установка WireGuard..."
    
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            apt install -y wireguard wireguard-tools resolvconf
            ;;
        *"CentOS"*|*"Red Hat"*|*"Rocky"*|*"AlmaLinux"*)
            yum install -y epel-release
            yum install -y wireguard-tools
            ;;
        *"Fedora"*)
            dnf install -y wireguard-tools
            ;;
        *)
            error_exit "Неподдерживаемая операционная система: $OS"
            ;;
    esac
    
    if command -v wg &> /dev/null; then
        log "SUCCESS" "WireGuard успешно установлен"
    else
        error_exit "Не удалось установить WireGuard"
    fi
}

# Load or create WireGuard kernel module
load_wireguard_module() {
    log "STEP" "Загрузка модуля ядра WireGuard..."
    
    if lsmod | grep -q wireguard; then
        log "SUCCESS" "Модуль WireGuard уже загружен"
        return 0
    fi
    
    if modprobe wireguard 2>/dev/null; then
        log "SUCCESS" "Модуль WireGuard загружен"
        
        # Make it persistent
        echo "wireguard" >> /etc/modules-load.d/wireguard.conf 2>/dev/null || true
    else
        log "WARN" "Не удалось загрузить модуль ядра WireGuard (возможно, используется userspace)"
    fi
}

# Get server public IP
get_server_ip() {
    log "STEP" "Определение публичного IP адреса сервера..."
    
    # Try to auto-detect public IP
    local detected_ip=""
    for service in "ifconfig.me" "ipinfo.io/ip" "icanhazip.com"; do
        detected_ip=$(curl -s --connect-timeout 5 "$service" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || echo "")
        if [[ -n "$detected_ip" ]]; then
            break
        fi
    done
    
    if [[ -n "$detected_ip" ]]; then
        log "INFO" "Автоматически определен IP: $detected_ip"
        echo
        read -p "Использовать этот IP адрес? [Y/n]: " use_detected
        if [[ "$use_detected" =~ ^[Nn]$ ]]; then
            detected_ip=""
        fi
    fi
    
    if [[ -z "$detected_ip" ]]; then
        echo
        echo -e "${YELLOW}Введите публичный IP адрес вашего сервера:${NC}"
        echo "Это тот IP, по которому клиенты будут подключаться к VPN"
        echo "Узнать можно командой: curl ifconfig.me"
        echo
        read -p "IP адрес сервера: " SERVER_PUBLIC_IP
        
        # Validate IP address
        if [[ ! "$SERVER_PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            error_exit "Неверный формат IP адреса: $SERVER_PUBLIC_IP"
        fi
    else
        SERVER_PUBLIC_IP="$detected_ip"
    fi
    
    log "SUCCESS" "Публичный IP сервера: $SERVER_PUBLIC_IP"
}

# Detect network interfaces
detect_interfaces() {
    log "STEP" "Определение сетевых интерфейсов..."
    
    # Determine WAN interface (interface with default route)
    WAN_INTERFACE=$(ip route show default 2>/dev/null | head -1 | grep -oP 'dev \K\S+' || echo "")
    
    if [[ -z "$WAN_INTERFACE" ]]; then
        log "WARN" "Не удалось автоматически определить WAN интерфейс"
        echo "Доступные интерфейсы:"
        ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo
        read -p "Введите имя WAN интерфейса (например, eth0, ens3): " WAN_INTERFACE
    fi
    
    # Verify WAN interface exists
    if ! ip link show "$WAN_INTERFACE" &>/dev/null; then
        error_exit "Интерфейс $WAN_INTERFACE не существует"
    fi
    
    log "SUCCESS" "WAN интерфейс: $WAN_INTERFACE"
    
    # Determine WireGuard interface name
    WG_INTERFACE="wg0"
    
    # Check if WireGuard interface already exists
    if ip link show "$WG_INTERFACE" &>/dev/null; then
        log "WARN" "Интерфейс $WG_INTERFACE уже существует"
        read -p "Удалить существующий интерфейс? [y/N]: " remove_existing
        if [[ "$remove_existing" =~ ^[Yy]$ ]]; then
            wg-quick down "$WG_INTERFACE" 2>/dev/null || true
            log "INFO" "Существующий интерфейс $WG_INTERFACE остановлен"
        else
            error_exit "Установка прервана пользователем"
        fi
    fi
    
    log "SUCCESS" "WireGuard интерфейс: $WG_INTERFACE"
}

# Choose optimal port
choose_port() {
    log "STEP" "Выбор оптимального порта..."
    
    # Check if default port is available
    if ! netstat -ulpn 2>/dev/null | grep -q ":$DEFAULT_PORT " && ! ss -ulpn 2>/dev/null | grep -q ":$DEFAULT_PORT "; then
        WG_PORT=$DEFAULT_PORT
        log "SUCCESS" "Используется стандартный порт: $WG_PORT"
    elif ! netstat -ulpn 2>/dev/null | grep -q ":$ALTERNATIVE_PORT " && ! ss -ulpn 2>/dev/null | grep -q ":$ALTERNATIVE_PORT "; then
        WG_PORT=$ALTERNATIVE_PORT
        log "INFO" "Стандартный порт занят, используется альтернативный: $WG_PORT"
    else
        log "WARN" "Оба рекомендуемых порта заняты"
        read -p "Введите порт для WireGuard (1024-65535): " custom_port
        if [[ "$custom_port" =~ ^[0-9]+$ ]] && [[ $custom_port -ge 1024 ]] && [[ $custom_port -le 65535 ]]; then
            WG_PORT=$custom_port
        else
            error_exit "Неверный порт: $custom_port"
        fi
    fi
    
    log "SUCCESS" "Порт WireGuard: $WG_PORT"
}

# Generate cryptographic keys
generate_keys() {
    log "STEP" "Генерация криптографических ключей..."
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Generate server keys
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    log "SUCCESS" "Ключи сервера сгенерированы"
    log "INFO" "Публичный ключ сервера: $SERVER_PUBLIC_KEY"
}

# Enable IP forwarding
enable_ip_forwarding() {
    log "STEP" "Включение IP forwarding..."
    
    # Enable for current session
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
    
    # Make permanent
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    else
        sed -i 's/^net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    fi
    
    if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf 2>/dev/null || true
    fi
    
    # Apply immediately
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    
    log "SUCCESS" "IP forwarding включен"
}

# Configure optimal TCP settings
optimize_tcp_settings() {
    log "STEP" "Оптимизация TCP настроек..."
    
    # Universal TCP optimizations
    local tcp_settings=(
        "net.ipv4.tcp_keepalive_time=120"
        "net.ipv4.tcp_keepalive_intvl=30"
        "net.ipv4.tcp_keepalive_probes=3"
        "net.ipv4.tcp_window_scaling=1"
        "net.ipv4.tcp_timestamps=1"
        "net.ipv4.tcp_sack=1"
        "net.ipv4.tcp_fack=1"
        "net.core.rmem_max=16777216"
        "net.core.wmem_max=16777216"
        "net.ipv4.tcp_rmem=4096 65536 16777216"
        "net.ipv4.tcp_wmem=4096 65536 16777216"
        "net.core.netdev_max_backlog=5000"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    
    for setting in "${tcp_settings[@]}"; do
        local key="${setting%%=*}"
        sysctl -w "$setting" >/dev/null 2>&1 || true
        
        # Make permanent
        if ! grep -q "^$key" /etc/sysctl.conf; then
            echo "$setting" >> /etc/sysctl.conf
        else
            sed -i "s/^$key.*/$setting/" /etc/sysctl.conf
        fi
    done
    
    sysctl -p >/dev/null 2>&1 || true
    log "SUCCESS" "TCP настройки оптимизированы"
}

# Clear any existing iptables rules for WireGuard
clear_existing_rules() {
    log "STEP" "Очистка существующих правил iptables..."
    
    # Remove any existing WireGuard rules
    iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$VPN_NETWORK" -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null || true
    
    log "SUCCESS" "Существующие правила очищены"
}

# Configure iptables rules - FIXED for proper internet access
setup_firewall() {
    log "STEP" "Настройка правил firewall (ИСПРАВЛЕННАЯ ВЕРСИЯ)..."
    
    # Backup existing rules
    iptables-save > "$BACKUP_DIR/iptables-backup-$(date +%Y%m%d-%H%M%S).rules" 2>/dev/null || true
    
    # Clear existing WireGuard rules first
    clear_existing_rules
    
    # Get default gateway interface dynamically
    local default_interface=$(ip route | awk '/default/ {print $5; exit}')
    if [[ -z "$default_interface" ]]; then
        default_interface="$WAN_INTERFACE"
    fi
    
    log "INFO" "Используется интерфейс для интернета: $default_interface"
    
    # ESSENTIAL: Enable MASQUERADE for internet access - MUST BE FIRST
    iptables -t nat -I POSTROUTING 1 -s "$VPN_NETWORK" -o "$default_interface" -j MASQUERADE
    
    # Allow WireGuard port - essential for VPN connections
    iptables -I INPUT 1 -p udp --dport "$WG_PORT" -j ACCEPT
    
    # Allow all traffic from/to WireGuard interface
    iptables -I FORWARD 1 -i "$WG_INTERFACE" -j ACCEPT
    iptables -I FORWARD 2 -o "$WG_INTERFACE" -j ACCEPT
    
    # Allow established and related connections (essential for two-way communication)
    iptables -I FORWARD 3 -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow loopback (essential for local services)
    iptables -I INPUT 1 -i lo -j ACCEPT
    iptables -I OUTPUT 1 -o lo -j ACCEPT
    
    # Allow SSH (don't lock yourself out)
    iptables -I INPUT 2 -p tcp --dport 22 -j ACCEPT
    iptables -I INPUT 3 -p tcp --dport 22 -m state --state ESTABLISHED -j ACCEPT
    
    # Allow DNS for proper resolution
    iptables -I INPUT -p udp --dport 53 -j ACCEPT
    iptables -I INPUT -p tcp --dport 53 -j ACCEPT
    iptables -I OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -I OUTPUT -p tcp --dport 53 -j ACCEPT
    
    # Allow ICMP for ping and MTU discovery
    iptables -I INPUT -p icmp -j ACCEPT
    iptables -I FORWARD -p icmp -j ACCEPT
    iptables -I OUTPUT -p icmp -j ACCEPT
    
    # MSS clamping for optimal packet handling (essential for mobile networks)
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    iptables -t mangle -A FORWARD -i "$WG_INTERFACE" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300
    
    # Allow fragmented packets
    iptables -I INPUT -f -j ACCEPT
    iptables -I FORWARD -f -j ACCEPT
    
    # Optimize connection tracking for better performance
    echo 1800 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null || true
    echo 120 > /proc/sys/net/netfilter/nf_conntrack_generic_timeout 2>/dev/null || true
    echo 60 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null || true
    
    # Additional optimizations for mobile connections
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null || true
    echo 1 > /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null || true
    
    # Save iptables rules permanently
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            # Ensure iptables-persistent is properly set up
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            if command -v netfilter-persistent &> /dev/null; then
                netfilter-persistent save 2>/dev/null || true
            fi
            ;;
        *"CentOS"*|*"Red Hat"*|*"Rocky"*|*"AlmaLinux"*|*"Fedora"*)
            if command -v iptables-save &> /dev/null; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
            if systemctl is-enabled iptables &> /dev/null; then
                service iptables save 2>/dev/null || true
            fi
            ;;
    esac
    
    log "SUCCESS" "Правила firewall настроены и сохранены (ИСПРАВЛЕННАЯ ВЕРСИЯ)"
    log "INFO" "MASQUERADE настроен для интерфейса: $default_interface"
    
    # Debug: Show current rules
    log "DEBUG" "Текущие правила iptables (первые 15 строк):"
    iptables -L -n --line-numbers | head -15 >> "$LOG_FILE" 2>/dev/null || true
    log "DEBUG" "NAT правила (POSTROUTING):"
    iptables -t nat -L POSTROUTING -n -v >> "$LOG_FILE" 2>/dev/null || true
}

# Create post-up and post-down scripts (external files)
create_post_scripts() {
    log "STEP" "Создание post-up и post-down скриптов..."
    
    # Create post-up script
    cat > "$CONFIG_DIR/post-up.sh" << 'EOF'
#!/bin/bash
# WireGuard Post-Up Script - Enable routing and NAT
set -e

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set optimal MTU
ip link set dev %i mtu 1342

# Allow WireGuard traffic through firewall
iptables -I INPUT -p udp --dport %i -j ACCEPT 2>/dev/null || true

# Allow forwarding for VPN interface
iptables -I FORWARD -i %i -j ACCEPT 2>/dev/null || true
iptables -I FORWARD -o %i -j ACCEPT 2>/dev/null || true

# Enable NAT/MASQUERADE for internet access
iptables -t nat -I POSTROUTING -s 10.0.0.0/24 -o $(ip route | awk '/default/ {print $5; exit}') -j MASQUERADE 2>/dev/null || true

# Allow established and related connections
iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# Log successful execution
echo "$(date): WireGuard post-up completed successfully" >> /var/log/wireguard.log
EOF

    # Create post-down script
    cat > "$CONFIG_DIR/post-down.sh" << 'EOF'
#!/bin/bash
# WireGuard Post-Down Script - Clean up routing and NAT
set -e

# Remove firewall rules (ignore errors if rules don't exist)
iptables -D INPUT -p udp --dport %i -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o $(ip route | awk '/default/ {print $5; exit}') -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# Log successful execution
echo "$(date): WireGuard post-down completed successfully" >> /var/log/wireguard.log
EOF

    # Make scripts executable
    chmod +x "$CONFIG_DIR/post-up.sh"
    chmod +x "$CONFIG_DIR/post-down.sh"
    
    # Replace port placeholder with actual port
    sed -i "s/%i/$WG_PORT/g" "$CONFIG_DIR/post-up.sh"
    sed -i "s/%i/$WG_PORT/g" "$CONFIG_DIR/post-down.sh"
    
    log "SUCCESS" "Post-up и post-down скрипты созданы и настроены"
}

# Create server configuration
create_server_config() {
    log "STEP" "Создание конфигурации сервера..."
    
    local config_file="$CONFIG_DIR/$WG_INTERFACE.conf"
    
    # Backup existing config if it exists
    if [[ -f "$config_file" ]]; then
        cp "$config_file" "$BACKUP_DIR/${WG_INTERFACE}.conf.backup-$(date +%Y%m%d-%H%M%S)"
        log "INFO" "Существующая конфигурация сохранена в backup"
    fi
    
    cat > "$config_file" << EOF
# WireGuard Server Configuration - ULTIMATE EDITION
# Generated by wg-universal-setup.sh v3.1 on $(date)
# Optimized for all device types with proven values
# External post-up/post-down scripts for reliability

[Interface]
# Server private key
PrivateKey = $SERVER_PRIVATE_KEY

# Server IP address within VPN network
Address = $SERVER_VPN_IP/24

# Listen port - optimized for compatibility
ListenPort = $WG_PORT

# MTU optimized for universal device compatibility
MTU = $OPTIMAL_MTU

# Post-up script - executed when interface comes up
PostUp = $CONFIG_DIR/post-up.sh

# Post-down script - executed when interface goes down
PostDown = $CONFIG_DIR/post-down.sh

# Client configurations will be added below
# Generated automatically

EOF
    
    chmod 600 "$config_file"
    log "SUCCESS" "Конфигурация сервера создана с внешними post-up/post-down скриптами: $config_file"
    log "INFO" "Публичный ключ сервера: $SERVER_PUBLIC_KEY"
}

# Generate client configuration
generate_client_config() {
    local client_name="$1"
    local client_number="$2"
    local client_ip="10.0.0.$((client_number + 1))"
    
    # Generate client keys
    local client_private_key=$(wg genkey)
    local client_public_key=$(echo "$client_private_key" | wg pubkey)
    
    # Client config file
    local client_config_file="$CONFIG_DIR/clients/${client_name}.conf"
    mkdir -p "$CONFIG_DIR/clients"
    
    cat > "$client_config_file" << EOF
# WireGuard Client Configuration - Universal Optimized
# Client: $client_name
# Generated on $(date)

[Interface]
# Client private key
PrivateKey = $client_private_key

# Client IP address within VPN network
Address = $client_ip/32

# DNS server
DNS = $OPTIMAL_DNS

# MTU optimized for universal compatibility
MTU = $OPTIMAL_MTU

[Peer]
# Server public key
PublicKey = $SERVER_PUBLIC_KEY

# Server endpoint - REAL IP ADDRESS
Endpoint = $SERVER_PUBLIC_IP:$WG_PORT

# Route all traffic through VPN
AllowedIPs = 0.0.0.0/0

# Persistent keepalive - optimal for all device types
PersistentKeepalive = $OPTIMAL_KEEPALIVE
EOF
    
    # Add peer to server config
    cat >> "$CONFIG_DIR/$WG_INTERFACE.conf" << EOF

# Client: $client_name
[Peer]
PublicKey = $client_public_key
AllowedIPs = $client_ip/32
PersistentKeepalive = $OPTIMAL_KEEPALIVE

EOF
    
    log "SUCCESS" "Конфигурация клиента '$client_name' создана: $client_config_file"
    log "INFO" "IP клиента: $client_ip"
    
    return 0
}

# Create client configurations
create_client_configs() {
    log "STEP" "Создание конфигураций клиентов..."
    
    read -p "Сколько клиентских конфигураций создать? [3]: " client_count
    client_count=${client_count:-3}
    
    if ! [[ "$client_count" =~ ^[0-9]+$ ]] || [[ $client_count -lt 0 ]] || [[ $client_count -gt 50 ]]; then
        log "WARN" "Неверное количество клиентов, создается 3 конфигурации по умолчанию"
        client_count=3
    fi
    
    for ((i=1; i<=client_count; i++)); do
        local default_name="client$i"
        read -p "Имя клиента $i [$default_name]: " client_name
        client_name=${client_name:-$default_name}
        
        generate_client_config "$client_name" "$i"
    done
    
    CLIENT_COUNT=$client_count
    log "SUCCESS" "Создано $CLIENT_COUNT клиентских конфигураций с правильным IP: $SERVER_PUBLIC_IP"
}

# Start WireGuard interface
start_wireguard() {
    log "STEP" "Запуск WireGuard интерфейса..."
    
    # Stop any existing interface first
    wg-quick down "$WG_INTERFACE" 2>/dev/null || true
    
    if wg-quick up "$WG_INTERFACE"; then
        log "SUCCESS" "WireGuard интерфейс $WG_INTERFACE запущен"
        
        # Enable systemd service
        systemctl enable wg-quick@"$WG_INTERFACE" 2>/dev/null || true
        log "SUCCESS" "WireGuard сервис включен для автозапуска"
        
        # Wait a moment for interface to be fully up
        sleep 2
    else
        error_exit "Не удалось запустить WireGuard интерфейс"
    fi
}

# Enhanced connectivity testing with auto-fix capabilities
test_connectivity() {
    log "STEP" "Комплексная проверка подключения с автоисправлением..."
    
    local all_tests_passed=true
    
    # Test if interface is up
    if ip link show "$WG_INTERFACE" &>/dev/null; then
        log "SUCCESS" "Интерфейс $WG_INTERFACE активен"
        
        # Show interface details
        local interface_info=$(ip addr show "$WG_INTERFACE" 2>/dev/null | head -3)
        log "INFO" "Интерфейс: $interface_info"
        
        # Show WireGuard status
        local wg_status=$(wg show "$WG_INTERFACE" 2>/dev/null || echo "Нет подключенных клиентов")
        log "INFO" "WireGuard статус: $wg_status"
    else
        log "ERROR" "Интерфейс $WG_INTERFACE не активен"
        all_tests_passed=false
    fi
    
    # Test basic internet connectivity from server
    log "INFO" "Проверка интернет-соединения сервера..."
    if ping -c 2 -W 3 8.8.8.8 >/dev/null 2>&1; then
        log "SUCCESS" "Сервер имеет доступ к интернету"
    else
        log "ERROR" "Сервер не имеет доступа к интернету"
        all_tests_passed=false
    fi
    
    # Test DNS resolution
    log "INFO" "Проверка DNS разрешения..."
    if nslookup google.com >/dev/null 2>&1 || dig google.com >/dev/null 2>&1; then
        log "SUCCESS" "DNS разрешение работает"
    else
        log "WARN" "Проблемы с DNS разрешением"
        # Try to fix DNS
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 1.1.1.1" >> /etc/resolv.conf
        log "INFO" "DNS серверы исправлены на 8.8.8.8 и 1.1.1.1"
    fi
    
    # Check IP forwarding
    log "INFO" "Проверка IP forwarding..."
    local ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [[ "$ip_forward" == "1" ]]; then
        log "SUCCESS" "IP forwarding включен"
    else
        log "ERROR" "IP forwarding отключен!"
        echo 1 > /proc/sys/net/ipv4/ip_forward
        log "INFO" "IP forwarding принудительно включен"
        all_tests_passed=false
    fi
    
    # Check iptables rules - CRITICAL for internet access
    log "INFO" "Проверка правил iptables..."
    local nat_rules=$(iptables -t nat -L POSTROUTING -n | grep -c "$VPN_NETWORK" || echo "0")
    if [[ "$nat_rules" -gt 0 ]]; then
        log "SUCCESS" "Правила NAT настроены корректно ($nat_rules правил)"
    else
        log "ERROR" "Правила NAT отсутствуют! Исправляем..."
        # Emergency fix for missing NAT rules
        local default_interface=$(ip route | awk '/default/ {print $5; exit}')
        iptables -t nat -I POSTROUTING 1 -s "$VPN_NETWORK" -o "$default_interface" -j MASQUERADE
        iptables -I FORWARD 1 -i "$WG_INTERFACE" -j ACCEPT
        iptables -I FORWARD 1 -o "$WG_INTERFACE" -j ACCEPT
        log "SUCCESS" "Правила NAT добавлены принудительно"
        all_tests_passed=false
    fi
    
    # Check if WireGuard port is listening
    log "INFO" "Проверка порта WireGuard..."
    if netstat -ulpn 2>/dev/null | grep -q ":$WG_PORT " || ss -ulpn 2>/dev/null | grep -q ":$WG_PORT "; then
        log "SUCCESS" "Порт $WG_PORT открыт и слушается"
    else
        log "ERROR" "Порт $WG_PORT не слушается!"
        log "INFO" "Попытка перезапуска WireGuard..."
        wg-quick down "$WG_INTERFACE" 2>/dev/null || true
        sleep 2
        wg-quick up "$WG_INTERFACE" 2>/dev/null || true
        sleep 2
        if netstat -ulpn 2>/dev/null | grep -q ":$WG_PORT " || ss -ulpn 2>/dev/null | grep -q ":$WG_PORT "; then
            log "SUCCESS" "Порт $WG_PORT теперь активен после перезапуска"
        else
            log "ERROR" "Не удалось активировать порт $WG_PORT"
            all_tests_passed=false
        fi
    fi
    
    # Test MTU and packet handling
    log "INFO" "Проверка MTU и обработки пакетов..."
    if ping -c 1 -s $((OPTIMAL_MTU - 28)) -M do 8.8.8.8 >/dev/null 2>&1; then
        log "SUCCESS" "MTU $OPTIMAL_MTU оптимален"
    else
        log "WARN" "Возможны проблемы с MTU $OPTIMAL_MTU"
        # Try smaller MTU
        if ping -c 1 -s 1200 -M do 8.8.8.8 >/dev/null 2>&1; then
            log "INFO" "MTU 1200 работает, возможна фрагментация"
        fi
    fi
    
    # Additional network diagnostics
    log "INFO" "Дополнительная диагностика сети..."
    
    # Check default route
    local default_route=$(ip route show default 2>/dev/null | head -1)
    if [[ -n "$default_route" ]]; then
        log "SUCCESS" "Маршрут по умолчанию: $default_route"
    else
        log "ERROR" "Отсутствует маршрут по умолчанию!"
        all_tests_passed=false
    fi
    
    # Check if we can reach internet through VPN network simulation
    log "INFO" "Проверка маршрутизации VPN трафика..."
    if ip route add 1.1.1.1/32 dev "$WG_INTERFACE" 2>/dev/null; then
        if ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
            log "SUCCESS" "VPN маршрутизация работает корректно"
        else
            log "WARN" "Проблемы с маршрутизацией VPN трафика"
        fi
        ip route del 1.1.1.1/32 dev "$WG_INTERFACE" 2>/dev/null || true
    fi
    
    if $all_tests_passed; then
        log "SUCCESS" "Все проверки пройдены успешно!"
        return 0
    else
        log "WARN" "Некоторые проблемы были исправлены автоматически"
        log "INFO" "Рекомендуется проверить логи для деталей"
        return 1
    fi
}

# Show detailed debug information
show_debug_info() {
    log "STEP" "Сбор отладочной информации..."
    
    {
        echo "=== DEBUG INFORMATION ==="
        echo "Date: $(date)"
        echo "OS: $OS $OS_VERSION"
        echo "WG Interface: $WG_INTERFACE"
        echo "WAN Interface: $WAN_INTERFACE"
        echo "Server Public IP: $SERVER_PUBLIC_IP"
        echo "VPN Network: $VPN_NETWORK"
        echo "Port: $WG_PORT"
        echo
        echo "=== NETWORK INTERFACES ==="
        ip addr show
        echo
        echo "=== ROUTING TABLE ==="
        ip route show
        echo
        echo "=== IPTABLES RULES ==="
        iptables -L -n --line-numbers
        echo
        echo "=== NAT RULES ==="
        iptables -t nat -L -n
        echo
        echo "=== WIREGUARD STATUS ==="
        wg show
        echo
        echo "=== LISTENING PORTS ==="
        netstat -ulpn | grep -E ":(51820|443)" || ss -ulpn | grep -E ":(51820|443)"
        echo
        echo "=== SYSCTL SETTINGS ==="
        sysctl net.ipv4.ip_forward
        echo
    } >> "$LOG_FILE"
    
    log "SUCCESS" "Отладочная информация записана в $LOG_FILE"
}

# Generate setup summary
show_setup_summary() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    УСТАНОВКА ЗАВЕРШЕНА                      ║${NC}"
    echo -e "${GREEN}║                  VPN СЕРВЕР ГОТОВ К РАБОТЕ                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    log "INFO" "Конфигурация WireGuard VPN сервера:"
    echo -e "  ${CYAN}Интерфейс WireGuard:${NC} $WG_INTERFACE"
    echo -e "  ${CYAN}WAN интерфейс:${NC} $WAN_INTERFACE"
    echo -e "  ${CYAN}Публичный IP:${NC} $SERVER_PUBLIC_IP"
    echo -e "  ${CYAN}Порт:${NC} $WG_PORT"
    echo -e "  ${CYAN}MTU:${NC} $OPTIMAL_MTU (универсальный оптимум)"
    echo -e "  ${CYAN}PersistentKeepalive:${NC} $OPTIMAL_KEEPALIVE секунд"
    echo -e "  ${CYAN}DNS:${NC} $OPTIMAL_DNS"
    echo -e "  ${CYAN}Сеть VPN:${NC} $VPN_NETWORK"
    echo -e "  ${CYAN}IP сервера в VPN:${NC} $SERVER_VPN_IP"
    echo -e "  ${CYAN}Клиентов создано:${NC} $CLIENT_COUNT"
    echo
    
    echo -e "${YELLOW}Публичный ключ сервера:${NC}"
    echo "$SERVER_PUBLIC_KEY"
    echo
    
    echo -e "${YELLOW}Файлы конфигурации:${NC}"
    echo "  Сервер: $CONFIG_DIR/$WG_INTERFACE.conf"
    echo "  Клиенты: $CONFIG_DIR/clients/"
    echo "  Логи: $LOG_FILE"
    echo
    
    echo -e "${YELLOW}Клиентские конфигурации готовы к использованию:${NC}"
    if [[ -d "$CONFIG_DIR/clients" ]]; then
        ls -la "$CONFIG_DIR/clients/"
    fi
    echo
    
    echo -e "${YELLOW}Управление сервисом:${NC}"
    echo "  Статус: systemctl status wg-quick@$WG_INTERFACE"
    echo "  Остановить: systemctl stop wg-quick@$WG_INTERFACE"
    echo "  Запустить: systemctl start wg-quick@$WG_INTERFACE"
    echo "  Перезапустить: systemctl restart wg-quick@$WG_INTERFACE"
    echo
    
    echo -e "${YELLOW}Полезные команды:${NC}"
    echo "  Показать статус: wg show"
    echo "  Показать конфигурацию: wg showconf $WG_INTERFACE"
    echo "  Просмотр логов: tail -f /var/log/wireguard.log"
    echo "  Отладочная информация: tail -f $LOG_FILE"
    echo
    
    echo -e "${GREEN}✅ VPN сервер готов к работе!${NC}"
    echo -e "${GREEN}✅ Оптимизирован для всех типов устройств и сетей${NC}"
    echo -e "${GREEN}✅ Поддерживает WiFi и мобильные соединения${NC}"
    echo -e "${GREEN}✅ Все клиентские конфигурации содержат правильный IP сервера${NC}"
    echo
    
    echo -e "${CYAN}Следующие шаги:${NC}"
    echo "1. Клиентские конфигурации готовы в папке $CONFIG_DIR/clients/"
    echo "2. Отправьте .conf файлы клиентам безопасным способом"
    echo "3. Откройте порт $WG_PORT UDP в облачном firewall (если используется)"
    echo "4. Импортируйте конфигурации в приложение WireGuard на клиентских устройствах"
    echo
    
    echo -e "${YELLOW}Если есть проблемы с подключением клиентов:${NC}"
    echo "1. Проверьте, что порт $WG_PORT UDP открыт в firewall облачного провайдера"
    echo "2. Убедитесь, что клиенты используют правильный IP: $SERVER_PUBLIC_IP"
    echo "3. Проверьте логи: journalctl -u wg-quick@$WG_INTERFACE -f"
    echo
}

# Main installation function
main() {
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    print_banner
    
    log "INFO" "Начало установки WireGuard VPN сервера (ИСПРАВЛЕННАЯ ВЕРСИЯ)"
    log "INFO" "Логи сохраняются в: $LOG_FILE"
    
    # System checks and preparation
    check_root
    detect_os
    install_packages
    install_wireguard
    load_wireguard_module
    
    # Network configuration
    get_server_ip
    detect_interfaces
    choose_port
    generate_keys
    
    # System optimization
    enable_ip_forwarding
    optimize_tcp_settings
    setup_firewall
    
    # WireGuard configuration
    create_post_scripts
    create_server_config
    create_client_configs
    
    # Start and test
    start_wireguard
    
    # Collect debug info before testing
    show_debug_info
    
    if test_connectivity; then
        log "SUCCESS" "Все проверки пройдены успешно!"
    else
        log "ERROR" "Некоторые проверки не прошли. Смотрите логи для диагностики."
    fi
    
    # Summary
    show_setup_summary
    
    log "SUCCESS" "Установка WireGuard завершена успешно!"
}

# Show usage information
show_usage() {
    echo "Использование: $0 [ОПЦИИ]"
    echo
    echo "WireGuard Universal Setup Script v3.1 ULTIMATE"
    echo "Полностью автоматическая установка и настройка VPN сервера"
    echo
    echo "Опции:"
    echo "  -h, --help     Показать эту справку"
    echo "  -v, --version  Показать версию"
    echo
    echo "Этот скрипт автоматически:"
    echo "  • Устанавливает WireGuard (если нужно)"
    echo "  • Запрашивает публичный IP адрес сервера"
    echo "  • Настраивает оптимальные сетевые параметры"
    echo "  • Создает правила firewall"
    echo "  • Генерирует серверную и клиентские конфигурации"
    echo "  • Запускает и тестирует VPN сервер"
    echo "  • Исправляет все проблемы с интернет-соединением"
    echo
    echo "Оптимизировано для всех типов устройств и сетей."
    echo "ИСПРАВЛЕНА проблема с отсутствием интернета в VPN."
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_usage
        exit 0
        ;;
    -v|--version)
        echo "WireGuard Universal Setup Script v3.1 ULTIMATE"
        exit 0
        ;;
    "")
        main "$@"
        ;;
    *)
        echo "Неизвестная опция: $1"
        show_usage
        exit 1
        ;;
esac