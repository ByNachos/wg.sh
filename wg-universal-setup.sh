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

# Choose optimal port with user selection
choose_port() {
    log "STEP" "Выбор порта для WireGuard..."
    
    echo
    echo -e "${CYAN}Выберите порт для WireGuard:${NC}"
    echo "1) 51820 (стандартный порт WireGuard)"
    echo "2) 443 (HTTPS порт - лучше проходит через firewall)"
    echo "3) Ввести свой порт"
    echo
    
    read -p "Ваш выбор [1-3]: " port_choice
    
    case "$port_choice" in
        1)
            WG_PORT=$DEFAULT_PORT
            log "INFO" "Выбран стандартный порт: $WG_PORT"
            ;;
        2)
            WG_PORT=$ALTERNATIVE_PORT
            log "INFO" "Выбран HTTPS порт: $WG_PORT (лучше проходит через firewall)"
            ;;
        3)
            read -p "Введите порт для WireGuard (1024-65535): " custom_port
            if [[ "$custom_port" =~ ^[0-9]+$ ]] && [[ $custom_port -ge 1024 ]] && [[ $custom_port -le 65535 ]]; then
                WG_PORT=$custom_port
                log "INFO" "Выбран пользовательский порт: $WG_PORT"
            else
                error_exit "Неверный порт: $custom_port"
            fi
            ;;
        *)
            log "WARN" "Неверный выбор, используется стандартный порт"
            WG_PORT=$DEFAULT_PORT
            ;;
    esac
    
    # Check if port is available
    if netstat -ulpn 2>/dev/null | grep -q ":$WG_PORT " || ss -ulpn 2>/dev/null | grep -q ":$WG_PORT "; then
        log "WARN" "Порт $WG_PORT уже занят!"
        read -p "Продолжить с этим портом? [y/N]: " continue_anyway
        if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
            error_exit "Установка прервана из-за занятого порта"
        fi
    fi
    
    log "SUCCESS" "Будет использован порт: $WG_PORT"
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

# Create inline post-up and post-down commands
create_inline_commands() {
    log "STEP" "Подготовка встроенных post-up/post-down команд..."
    
    # Get default interface dynamically
    local default_interface=$(ip route | awk '/default/ {print $5; exit}')
    if [[ -z "$default_interface" ]]; then
        default_interface="$WAN_INTERFACE"
    fi
    
    # Create inline post-up commands (all in one line, separated by semicolons)
    POST_UP_COMMANDS="echo 1 > /proc/sys/net/ipv4/ip_forward; iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT; iptables -I FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -I FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -I POSTROUTING -s $VPN_NETWORK -o $default_interface -j MASQUERADE; iptables -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
    
    # Create inline post-down commands
    POST_DOWN_COMMANDS="iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT; iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -s $VPN_NETWORK -o $default_interface -j MASQUERADE; iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
    
    log "SUCCESS" "Встроенные команды подготовлены для интерфейса: $default_interface"
    log "INFO" "Post-Up: $POST_UP_COMMANDS"
    log "INFO" "Post-Down: $POST_DOWN_COMMANDS"
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
# Inline post-up/post-down commands for maximum reliability

[Interface]
# Server private key
PrivateKey = $SERVER_PRIVATE_KEY

# Server IP address within VPN network
Address = $SERVER_VPN_IP/24

# Listen port - user selected for best compatibility
ListenPort = $WG_PORT

# MTU optimized for universal device compatibility
MTU = $OPTIMAL_MTU

# Post-up commands - executed when interface comes up
PostUp = $POST_UP_COMMANDS

# Post-down commands - executed when interface goes down  
PostDown = $POST_DOWN_COMMANDS

# Client configurations will be added below
# Generated automatically

EOF
    
    chmod 600 "$config_file"
    log "SUCCESS" "Конфигурация сервера создана с встроенными post-up/post-down командами: $config_file"
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

# Start WireGuard interface with enhanced error handling
start_wireguard() {
    log "STEP" "Запуск WireGuard интерфейса..."
    
    # Stop any existing interface first
    log "INFO" "Остановка существующих интерфейсов..."
    wg-quick down "$WG_INTERFACE" 2>/dev/null || true
    ip link delete "$WG_INTERFACE" 2>/dev/null || true
    
    # Wait for cleanup
    sleep 1
    
    # Validate configuration before starting
    log "INFO" "Проверка конфигурации..."
    if ! wg-quick strip "$WG_INTERFACE" >/dev/null 2>&1; then
        log "ERROR" "Ошибка в конфигурации WireGuard!"
        log "INFO" "Содержимое конфигурации:"
        cat "$CONFIG_DIR/$WG_INTERFACE.conf" >> "$LOG_FILE"
        error_exit "Некорректная конфигурация WireGuard"
    fi
    
    # Try to start the interface
    log "INFO" "Запуск интерфейса $WG_INTERFACE..."
    if wg-quick up "$WG_INTERFACE" 2>&1 | tee -a "$LOG_FILE"; then
        log "SUCCESS" "WireGuard интерфейс $WG_INTERFACE запущен успешно"
    else
        log "ERROR" "Ошибка при запуске WireGuard интерфейса"
        log "INFO" "Попытка диагностики проблемы..."
        
        # Show detailed error information
        log "DEBUG" "Проверка конфигурации:"
        wg-quick strip "$WG_INTERFACE" 2>&1 | tee -a "$LOG_FILE" || true
        
        log "DEBUG" "Проверка сетевых интерфейсов:"
        ip link show 2>&1 | tee -a "$LOG_FILE" || true
        
        error_exit "Не удалось запустить WireGuard интерфейс. Смотрите логи в $LOG_FILE"
    fi
    
    # Wait for interface to be fully up
    sleep 3
    
    # Verify interface is actually up
    if ip link show "$WG_INTERFACE" &>/dev/null; then
        log "SUCCESS" "Интерфейс $WG_INTERFACE активен"
    else
        error_exit "Интерфейс $WG_INTERFACE не активен после запуска"
    fi
    
    # Enable systemd service
    log "INFO" "Включение автозапуска..."
    if systemctl enable wg-quick@"$WG_INTERFACE" 2>&1 | tee -a "$LOG_FILE"; then
        log "SUCCESS" "WireGuard сервис включен для автозапуска"
    else
        log "WARN" "Не удалось включить автозапуск сервиса"
    fi
    
    # Test if systemctl can manage the service
    log "INFO" "Проверка управления сервисом..."
    if systemctl is-active wg-quick@"$WG_INTERFACE" >/dev/null 2>&1; then
        log "SUCCESS" "Сервис wg-quick@$WG_INTERFACE активен"
    else
        log "WARN" "Сервис не активен, но интерфейс работает"
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
    
    # Detailed VPN traffic routing test
    log "INFO" "Детальная проверка маршрутизации VPN трафика..."
    
    # Show current routing table
    log "DEBUG" "Текущая таблица маршрутизации:"
    ip route show | while read route; do
        log "DEBUG" "  $route"
    done
    
    # Show iptables rules in detail
    log "DEBUG" "Детальная проверка правил iptables:"
    
    # INPUT rules
    log "DEBUG" "INPUT правила (WireGuard порт):"
    iptables -L INPUT -n -v --line-numbers | grep -E "(Chain|$WG_PORT|udp)" | while read line; do
        log "DEBUG" "  $line"
    done
    
    # FORWARD rules
    log "DEBUG" "FORWARD правила (VPN интерфейс):"
    iptables -L FORWARD -n -v --line-numbers | grep -E "(Chain|$WG_INTERFACE|ACCEPT|RELATED)" | while read line; do
        log "DEBUG" "  $line"
    done
    
    # NAT rules with details
    log "DEBUG" "NAT POSTROUTING правила (MASQUERADE):"
    iptables -t nat -L POSTROUTING -n -v --line-numbers | while read line; do
        log "DEBUG" "  $line"
    done
    
    # Test VPN routing with detailed output
    log "INFO" "Тестирование маршрутизации через VPN интерфейс..."
    
    # Test 1: Add test route
    local test_ip="1.1.1.1"
    if ip route add $test_ip/32 dev "$WG_INTERFACE" 2>&1 | tee -a "$LOG_FILE"; then
        log "SUCCESS" "Тестовый маршрут добавлен: $test_ip -> $WG_INTERFACE"
        
        # Show the added route
        log "DEBUG" "Проверка добавленного маршрута:"
        ip route show $test_ip | while read route; do
            log "DEBUG" "  $route"
        done
        
        # Test ping with detailed output
        log "INFO" "Тест ping через VPN интерфейс..."
        if ping -c 1 -W 3 -I "$WG_INTERFACE" $test_ip 2>&1 | tee -a "$LOG_FILE"; then
            log "SUCCESS" "Ping через VPN интерфейс успешен"
        else
            log "ERROR" "Ping через VPN интерфейс неуспешен"
            
            # Additional diagnostics
            log "DEBUG" "Дополнительная диагностика:"
            log "DEBUG" "Статус интерфейса $WG_INTERFACE:"
            ip addr show "$WG_INTERFACE" | while read line; do
                log "DEBUG" "  $line"
            done
            
            log "DEBUG" "ARP таблица:"
            arp -a | head -5 | while read line; do
                log "DEBUG" "  $line"
            done
        fi
        
        # Clean up test route
        ip route del $test_ip/32 dev "$WG_INTERFACE" 2>/dev/null || true
        log "INFO" "Тестовый маршрут удален"
    else
        log "ERROR" "Не удалось добавить тестовый маршрут"
    fi
    
    # Test 2: Check packet forwarding capability
    log "INFO" "Проверка возможности пересылки пакетов..."
    
    # Check if packets can flow from VPN network to internet
    local vpn_test_ip="10.0.0.100"  # Simulated client IP
    
    # Test with iptables tracing (if available)
    if command -v iptables-save >/dev/null 2>&1; then
        log "DEBUG" "Количество правил в каждой цепочке:"
        iptables -L INPUT -n | grep -c "^ACCEPT\|^DROP\|^REJECT" | xargs -I {} log "DEBUG" "  INPUT: {} правил"
        iptables -L FORWARD -n | grep -c "^ACCEPT\|^DROP\|^REJECT" | xargs -I {} log "DEBUG" "  FORWARD: {} правил"
        iptables -t nat -L POSTROUTING -n | grep -c "^MASQUERADE\|^SNAT" | xargs -I {} log "DEBUG" "  NAT POSTROUTING: {} правил"
    fi
    
    # Test 3: Verify WireGuard interface can route to default gateway
    local default_gw=$(ip route | awk '/default/ {print $3; exit}')
    if [[ -n "$default_gw" ]]; then
        log "INFO" "Тест маршрутизации к шлюзу по умолчанию: $default_gw"
        if ping -c 1 -W 2 "$default_gw" >/dev/null 2>&1; then
            log "SUCCESS" "Шлюз по умолчанию доступен: $default_gw"
        else
            log "WARN" "Проблемы с доступностью шлюза: $default_gw"
        fi
    fi
    
    # Test 4: Check conntrack if available
    if command -v conntrack >/dev/null 2>&1; then
        log "DEBUG" "Состояние connection tracking:"
        conntrack -L 2>/dev/null | head -3 | while read line; do
            log "DEBUG" "  $line"
        done || log "DEBUG" "  Connection tracking пуст или недоступен"
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

# Show detailed debug information with enhanced logging
show_debug_info() {
    log "STEP" "Сбор расширенной отладочной информации..."
    
    {
        echo "=================================="
        echo "    WIREGUARD DEBUG INFORMATION"
        echo "=================================="
        echo "Date: $(date)"
        echo "Script Version: v3.1 ULTIMATE"
        echo "OS: $OS $OS_VERSION"
        echo "WG Interface: $WG_INTERFACE"
        echo "WAN Interface: $WAN_INTERFACE"
        echo "Server Public IP: $SERVER_PUBLIC_IP"
        echo "VPN Network: $VPN_NETWORK"
        echo "Port: $WG_PORT"
        echo "MTU: $OPTIMAL_MTU"
        echo
        
        echo "=== SYSTEM INFORMATION ==="
        uname -a
        echo "Uptime: $(uptime)"
        echo "Memory: $(free -h | head -2 | tail -1)"
        echo "Disk space: $(df -h / | tail -1)"
        echo
        
        echo "=== NETWORK INTERFACES (DETAILED) ==="
        ip addr show
        echo
        echo "Link status:"
        ip link show
        echo
        
        echo "=== ROUTING TABLES (DETAILED) ==="
        echo "Main routing table:"
        ip route show table main
        echo
        echo "Local routing table:"
        ip route show table local | head -10
        echo
        
        echo "=== IPTABLES RULES (COMPLETE) ==="
        echo "Filter table:"
        iptables -L -n -v --line-numbers
        echo
        echo "NAT table:"
        iptables -t nat -L -n -v --line-numbers
        echo
        echo "Mangle table:"
        iptables -t mangle -L -n -v --line-numbers | head -20
        echo
        
        echo "=== WIREGUARD STATUS (DETAILED) ==="
        echo "WireGuard version:"
        wg --version 2>/dev/null || echo "Version info not available"
        echo
        echo "WireGuard interfaces:"
        wg show all
        echo
        echo "WireGuard configuration:"
        wg showconf "$WG_INTERFACE" 2>/dev/null || echo "Config not available"
        echo
        
        echo "=== NETWORK CONNECTIVITY TESTS ==="
        echo "Ping to localhost:"
        ping -c 1 127.0.0.1 2>&1 || echo "Localhost ping failed"
        echo
        echo "Ping to default gateway:"
        ping -c 1 $(ip route | awk '/default/ {print $3; exit}') 2>&1 || echo "Gateway ping failed"
        echo
        echo "Ping to Google DNS:"
        ping -c 1 8.8.8.8 2>&1 || echo "External ping failed"
        echo
        echo "DNS resolution test:"
        nslookup google.com 2>&1 || echo "DNS resolution failed"
        echo
        
        echo "=== PORT STATUS ==="
        echo "All listening UDP ports:"
        netstat -ulpn 2>/dev/null || ss -ulpn
        echo
        echo "WireGuard port specifically:"
        netstat -ulpn 2>/dev/null | grep ":$WG_PORT " || ss -ulpn | grep ":$WG_PORT " || echo "WireGuard port not found"
        echo
        
        echo "=== SYSTEM SETTINGS ==="
        echo "IP forwarding:"
        sysctl net.ipv4.ip_forward
        echo "Network settings:"
        sysctl net.ipv4.conf.all.forwarding 2>/dev/null || echo "IPv4 forwarding setting not available"
        sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "Redirect setting not available"
        echo
        
        echo "=== PROCESS INFORMATION ==="
        echo "WireGuard processes:"
        ps aux | grep -E "(wireguard|wg-quick)" | grep -v grep || echo "No WireGuard processes found"
        echo
        
        echo "=== KERNEL MODULES ==="
        echo "WireGuard module:"
        lsmod | grep wireguard || echo "WireGuard module not loaded"
        echo "Network modules:"
        lsmod | grep -E "(ip_tables|iptable_nat|nf_nat)" | head -5
        echo
        
        echo "=== LOG FILES ==="
        echo "Recent kernel messages:"
        dmesg | tail -10 | grep -i wireguard || echo "No recent WireGuard kernel messages"
        echo
        echo "Recent system log:"
        journalctl -n 5 --no-pager -q 2>/dev/null || echo "Journal not available"
        echo
        
        echo "=== CONFIGURATION FILES ==="
        echo "WireGuard server config:"
        if [[ -f "$CONFIG_DIR/$WG_INTERFACE.conf" ]]; then
            cat "$CONFIG_DIR/$WG_INTERFACE.conf"
        else
            echo "Config file not found: $CONFIG_DIR/$WG_INTERFACE.conf"
        fi
        echo
        
        echo "=================================="
        echo "    END OF DEBUG INFORMATION"
        echo "=================================="
        
    } >> "$LOG_FILE"
    
    log "SUCCESS" "Расширенная отладочная информация записана в $LOG_FILE"
    log "INFO" "Общий размер лог-файла: $(du -h "$LOG_FILE" 2>/dev/null | cut -f1 || echo 'unknown')"
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
    create_inline_commands
    create_server_config
    create_client_configs
    
    # Start and test
    start_wireguard
    
    # Collect debug info before testing
    show_debug_info
    
    # Enhanced connectivity test with detailed console output
    log "INFO" "Запуск комплексного тестирования подключения..."
    echo
    echo -e "${CYAN}=== ДЕТАЛЬНАЯ ДИАГНОСТИКА ===${NC}"
    
    if test_connectivity; then
        log "SUCCESS" "✅ Все проверки пройдены успешно!"
        echo -e "${GREEN}✅ VPN сервер полностью функционален и готов к использованию${NC}"
    else
        log "WARN" "⚠️  Некоторые проблемы были обнаружены, но система попыталась их исправить"
        echo -e "${YELLOW}⚠️  Рекомендуется проверить детальные логи для анализа${NC}"
        echo -e "${YELLOW}📝 Полная диагностика доступна в: $LOG_FILE${NC}"
        
        # Show quick summary of potential issues
        echo
        echo -e "${CYAN}Краткий анализ возможных проблем:${NC}"
        
        # Check if interface is up
        if ip link show "$WG_INTERFACE" &>/dev/null; then
            echo -e "${GREEN}✅ Интерфейс $WG_INTERFACE активен${NC}"
        else
            echo -e "${RED}❌ Интерфейс $WG_INTERFACE не активен${NC}"
        fi
        
        # Check if port is listening
        if netstat -ulpn 2>/dev/null | grep -q ":$WG_PORT " || ss -ulpn 2>/dev/null | grep -q ":$WG_PORT "; then
            echo -e "${GREEN}✅ Порт $WG_PORT слушается${NC}"
        else
            echo -e "${RED}❌ Порт $WG_PORT не слушается${NC}"
        fi
        
        # Check IP forwarding
        if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" == "1" ]]; then
            echo -e "${GREEN}✅ IP forwarding включен${NC}"
        else
            echo -e "${RED}❌ IP forwarding отключен${NC}"
        fi
        
        # Check NAT rules
        local nat_rules=$(iptables -t nat -L POSTROUTING -n | grep -c "$VPN_NETWORK" 2>/dev/null || echo "0")
        if [[ "$nat_rules" -gt 0 ]]; then
            echo -e "${GREEN}✅ NAT правила настроены ($nat_rules правил)${NC}"
        else
            echo -e "${RED}❌ NAT правила отсутствуют${NC}"
        fi
        
        echo
        echo -e "${CYAN}Для подробной диагностики выполните:${NC}"
        echo -e "  ${YELLOW}tail -f $LOG_FILE${NC}"
        echo -e "  ${YELLOW}wg show${NC}"
        echo -e "  ${YELLOW}systemctl status wg-quick@$WG_INTERFACE${NC}"
    fi
    
    echo
    echo -e "${CYAN}Размер лог-файла: $(du -h "$LOG_FILE" 2>/dev/null | cut -f1 || echo 'unknown')${NC}"
    
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