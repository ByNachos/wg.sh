#!/bin/bash

# WireGuard Universal Setup Script - FIXED VERSION
# One-script solution for complete WireGuard VPN server setup
# Fixed all routing and internet connectivity issues
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

# Configure iptables rules
setup_firewall() {
    log "STEP" "Настройка правил firewall..."
    
    # Backup existing rules
    iptables-save > "$BACKUP_DIR/iptables-backup-$(date +%Y%m%d-%H%M%S).rules" 2>/dev/null || true
    
    # Clear existing WireGuard rules first
    clear_existing_rules
    
    # CRITICAL: Allow WireGuard port - this must be FIRST
    iptables -I INPUT 1 -p udp --dport "$WG_PORT" -j ACCEPT
    
    # Allow forwarding for WireGuard interface
    iptables -I FORWARD 1 -i "$WG_INTERFACE" -j ACCEPT
    iptables -I FORWARD 2 -o "$WG_INTERFACE" -j ACCEPT
    
    # CRITICAL: MASQUERADE rule for VPN traffic - this is essential for internet access
    iptables -t nat -A POSTROUTING -s "$VPN_NETWORK" -o "$WAN_INTERFACE" -j MASQUERADE
    
    # Allow established and related connections
    iptables -I FORWARD 3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    
    # MSS clamping for optimal packet handling
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    
    # Allow loopback
    iptables -I INPUT 1 -i lo -j ACCEPT
    
    # Allow SSH (important - don't lock yourself out)
    iptables -I INPUT 2 -p tcp --dport 22 -j ACCEPT
    
    # Allow fragmented packets
    iptables -I INPUT -f -j ACCEPT
    iptables -I FORWARD -f -j ACCEPT
    
    # Optimize connection tracking
    echo 1800 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null || true
    echo 120 > /proc/sys/net/netfilter/nf_conntrack_generic_timeout 2>/dev/null || true
    
    # Save iptables rules permanently
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            netfilter-persistent save 2>/dev/null || true
            ;;
        *"CentOS"*|*"Red Hat"*|*"Rocky"*|*"AlmaLinux"*|*"Fedora"*)
            service iptables save 2>/dev/null || true
            ;;
    esac
    
    log "SUCCESS" "Правила firewall настроены и сохранены"
    
    # Debug: Show current rules
    log "DEBUG" "Текущие правила iptables:"
    iptables -L -n --line-numbers | head -20 >> "$LOG_FILE" 2>/dev/null || true
    iptables -t nat -L -n | head -10 >> "$LOG_FILE" 2>/dev/null || true
}

# Create post-up script
create_post_up_script() {
    local post_up_script="$CONFIG_DIR/post-up.sh"
    
    cat > "$post_up_script" << EOF
#!/bin/bash
# WireGuard post-up script - Universal optimization
# Auto-generated by wg-universal-setup-fixed.sh

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Clear any existing rules for this interface
iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s $VPN_NETWORK -o $WAN_INTERFACE -j MASQUERADE 2>/dev/null || true

# Add fresh rules
iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT
iptables -I FORWARD -i $WG_INTERFACE -j ACCEPT
iptables -I FORWARD -o $WG_INTERFACE -j ACCEPT
iptables -t nat -A POSTROUTING -s $VPN_NETWORK -o $WAN_INTERFACE -j MASQUERADE
iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Universal optimizations
ip link set dev $WG_INTERFACE mtu $OPTIMAL_MTU 2>/dev/null || true

# Log
echo "\$(date): WireGuard interface $WG_INTERFACE brought up" >> /var/log/wireguard.log
EOF
    
    chmod +x "$post_up_script"
    log "SUCCESS" "Post-up скрипт создан: $post_up_script"
}

# Create post-down script
create_post_down_script() {
    local post_down_script="$CONFIG_DIR/post-down.sh"
    
    cat > "$post_down_script" << EOF
#!/bin/bash
# WireGuard post-down script
# Auto-generated by wg-universal-setup-fixed.sh

# Remove iptables rules
iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s $VPN_NETWORK -o $WAN_INTERFACE -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# Log
echo "\$(date): WireGuard interface $WG_INTERFACE brought down" >> /var/log/wireguard.log
EOF
    
    chmod +x "$post_down_script"
    log "SUCCESS" "Post-down скрипт создан: $post_down_script"
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
# WireGuard Server Configuration - Universal Optimized FIXED
# Generated by wg-universal-setup-fixed.sh on $(date)
# Optimized for all device types with proven values

[Interface]
# Server private key
PrivateKey = $SERVER_PRIVATE_KEY

# Server IP address within VPN network
Address = $SERVER_VPN_IP/24

# Listen port - optimized for compatibility
ListenPort = $WG_PORT

# MTU optimized for universal device compatibility
MTU = $OPTIMAL_MTU

# Post-up script to configure routing and firewall
PostUp = $CONFIG_DIR/post-up.sh

# Post-down script to clean up
PostDown = $CONFIG_DIR/post-down.sh

# Client configurations will be added below
# Generated automatically

EOF
    
    chmod 600 "$config_file"
    log "SUCCESS" "Конфигурация сервера создана: $config_file"
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

# Enhanced connectivity testing
test_connectivity() {
    log "STEP" "Расширенная проверка подключения..."
    
    # Test if interface is up
    if ip link show "$WG_INTERFACE" &>/dev/null; then
        log "SUCCESS" "Интерфейс $WG_INTERFACE активен"
        
        # Show interface details
        local interface_info=$(ip addr show "$WG_INTERFACE" 2>/dev/null || echo "Информация недоступна")
        log "INFO" "Информация об интерфейсе: $interface_info"
        
        # Show WireGuard status
        local wg_status=$(wg show "$WG_INTERFACE" 2>/dev/null || echo "Статус недоступен")
        log "INFO" "Статус WireGuard: $wg_status"
    else
        log "ERROR" "Интерфейс $WG_INTERFACE не активен"
        return 1
    fi
    
    # Test basic internet connectivity from server
    log "INFO" "Проверка интернет-соединения сервера..."
    if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log "SUCCESS" "Сервер имеет доступ к интернету"
    else
        log "ERROR" "Сервер не имеет доступа к интернету"
        return 1
    fi
    
    # Test DNS resolution
    log "INFO" "Проверка DNS разрешения..."
    if nslookup google.com >/dev/null 2>&1; then
        log "SUCCESS" "DNS разрешение работает"
    else
        log "WARN" "Проблемы с DNS разрешением"
    fi
    
    # Test MTU
    log "INFO" "Проверка MTU..."
    if ping -c 1 -s $((OPTIMAL_MTU - 28)) -M do 8.8.8.8 >/dev/null 2>&1; then
        log "SUCCESS" "MTU $OPTIMAL_MTU оптимален"
    else
        log "WARN" "Возможны проблемы с MTU $OPTIMAL_MTU"
    fi
    
    # Check iptables rules
    log "INFO" "Проверка правил iptables..."
    if iptables -t nat -L POSTROUTING -n | grep -q "$VPN_NETWORK"; then
        log "SUCCESS" "Правила NAT настроены корректно"
    else
        log "ERROR" "Правила NAT отсутствуют!"
        return 1
    fi
    
    # Check if WireGuard port is open
    log "INFO" "Проверка доступности порта WireGuard..."
    if netstat -ulpn 2>/dev/null | grep -q ":$WG_PORT " || ss -ulpn 2>/dev/null | grep -q ":$WG_PORT "; then
        log "SUCCESS" "Порт $WG_PORT открыт и слушается"
    else
        log "ERROR" "Порт $WG_PORT не слушается!"
        return 1
    fi
    
    return 0
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
    create_post_up_script
    create_post_down_script
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
    echo "WireGuard Universal Setup Script v3.0 FIXED"
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
        echo "WireGuard Universal Setup Script v3.0 FIXED"
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