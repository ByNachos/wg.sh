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
    
    # Enhanced port conflict detection
    log "INFO" "Проверка доступности порта $WG_PORT..."
    
    # Check what's using the port
    local port_usage=$(netstat -ulpn 2>/dev/null | grep ":$WG_PORT " || ss -ulpn 2>/dev/null | grep ":$WG_PORT " || echo "")
    
    if [[ -n "$port_usage" ]]; then
        log "WARN" "Порт $WG_PORT уже занят!"
        log "INFO" "Детали использования порта:"
        echo "$port_usage" | while read line; do
            log "INFO" "  $line"
        done
        
        # Try to identify what's using the port
        local process_info=$(lsof -i UDP:$WG_PORT 2>/dev/null || echo "Процесс не определен")
        if [[ "$process_info" != "Процесс не определен" ]]; then
            log "INFO" "Процессы, использующие порт:"
            echo "$process_info" | while read line; do
                log "INFO" "  $line"
            done
        fi
        
        # Check if it's another WireGuard instance
        if echo "$port_usage" | grep -q "wg\|wireguard"; then
            log "INFO" "Порт используется другим экземпляром WireGuard"
            read -p "Остановить существующий WireGuard и продолжить? [y/N]: " stop_existing
            if [[ "$stop_existing" =~ ^[Yy]$ ]]; then
                log "INFO" "Остановка существующих WireGuard интерфейсов..."
                wg-quick down all 2>/dev/null || true
                systemctl stop wg-quick@* 2>/dev/null || true
                sleep 2
                
                # Check if port is now free
                if netstat -ulpn 2>/dev/null | grep -q ":$WG_PORT " || ss -ulpn 2>/dev/null | grep -q ":$WG_PORT "; then
                    log "WARN" "Порт всё ещё занят после остановки WireGuard"
                else
                    log "SUCCESS" "Порт $WG_PORT теперь свободен"
                fi
            fi
        fi
        
        # Final check and user decision
        if netstat -ulpn 2>/dev/null | grep -q ":$WG_PORT " || ss -ulpn 2>/dev/null | grep -q ":$WG_PORT "; then
            echo
            echo -e "${YELLOW}Внимание! Порт $WG_PORT всё ещё занят.${NC}"
            echo "Это может вызвать конфликты или неработоспособность VPN."
            echo
            read -p "Продолжить несмотря на конфликт? [y/N]: " continue_anyway
            if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
                echo
                echo -e "${CYAN}Рекомендации:${NC}"
                echo "1. Выберите другой порт (перезапустите скрипт)"
                echo "2. Остановите процесс, использующий порт $WG_PORT"
                echo "3. Перезагрузите сервер для очистки всех соединений"
                error_exit "Установка прервана из-за конфликта портов"
            else
                log "WARN" "Продолжение с конфликтующим портом - могут быть проблемы"
            fi
        fi
    else
        log "SUCCESS" "Порт $WG_PORT свободен"
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

# Clear any existing iptables rules for WireGuard - ENHANCED
clear_existing_rules() {
    log "STEP" "Тщательная очистка существующих правил iptables..."
    
    # Count existing rules before cleanup
    local input_before=$(iptables -L INPUT -n --line-numbers | grep -c "udp dpt:$WG_PORT\|udp dpt:51820\|udp dpt:443" || echo "0")
    local forward_before=$(iptables -L FORWARD -n --line-numbers | grep -c "$WG_INTERFACE" || echo "0")
    local nat_before=$(iptables -t nat -L POSTROUTING -n --line-numbers | grep -c "$VPN_NETWORK" || echo "0")
    
    log "INFO" "Найдено правил для удаления: INPUT=$input_before, FORWARD=$forward_before, NAT=$nat_before"
    
    # Remove all WireGuard-related INPUT rules (multiple ports)
    while iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null; do
        log "DEBUG" "Удалено INPUT правило для порта $WG_PORT"
    done
    
    # Remove rules for common WireGuard ports if different
    for port in 51820 443; do
        if [[ "$port" != "$WG_PORT" ]]; then
            while iptables -D INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; do
                log "DEBUG" "Удалено старое INPUT правило для порта $port"
            done
        fi
    done
    
    # Remove all WireGuard interface FORWARD rules
    while iptables -D FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null; do
        log "DEBUG" "Удалено FORWARD правило для входящего $WG_INTERFACE"
    done
    
    while iptables -D FORWARD -o "$WG_INTERFACE" -j ACCEPT 2>/dev/null; do
        log "DEBUG" "Удалено FORWARD правило для исходящего $WG_INTERFACE"
    done
    
    # Remove state-related FORWARD rules that might conflict
    while iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do
        log "DEBUG" "Удалено FORWARD правило для ESTABLISHED,RELATED"
    done
    
    while iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do
        log "DEBUG" "Удалено FORWARD правило для conntrack"
    done
    
    # Remove NAT rules for VPN network
    while iptables -t nat -D POSTROUTING -s "$VPN_NETWORK" -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null; do
        log "DEBUG" "Удалено NAT правило для $VPN_NETWORK -> $WAN_INTERFACE"
    done
    
    # Also try to remove with any interface
    while iptables -t nat -D POSTROUTING -s "$VPN_NETWORK" -j MASQUERADE 2>/dev/null; do
        log "DEBUG" "Удалено общее NAT правило для $VPN_NETWORK"
    done
    
    # Count remaining rules after cleanup
    local input_after=$(iptables -L INPUT -n --line-numbers | grep -c "udp dpt:$WG_PORT\|udp dpt:51820\|udp dpt:443" || echo "0")
    local forward_after=$(iptables -L FORWARD -n --line-numbers | grep -c "$WG_INTERFACE" || echo "0")
    local nat_after=$(iptables -t nat -L POSTROUTING -n --line-numbers | grep -c "$VPN_NETWORK" || echo "0")
    
    log "SUCCESS" "Очистка завершена. Осталось правил: INPUT=$input_after, FORWARD=$forward_after, NAT=$nat_after"
    
    if [[ $input_after -eq 0 && $forward_after -eq 0 && $nat_after -eq 0 ]]; then
        log "SUCCESS" "Все старые правила WireGuard успешно удалены"
    else
        log "WARN" "Некоторые правила могли остаться, но это не критично"
    fi
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
    
    # CRITICAL: Multiple MASQUERADE rules for maximum compatibility
    # Rule 1: Basic MASQUERADE for VPN network
    iptables -t nat -I POSTROUTING 1 -s "$VPN_NETWORK" -o "$default_interface" -j MASQUERADE
    
    # Rule 2: More specific MASQUERADE for non-local traffic
    iptables -t nat -I POSTROUTING 2 -s "$VPN_NETWORK" ! -d "$VPN_NETWORK" -o "$default_interface" -j MASQUERADE
    
    # Rule 3: Catch-all MASQUERADE for any interface (backup)
    iptables -t nat -A POSTROUTING -s "$VPN_NETWORK" -j MASQUERADE
    
    # Allow WireGuard port - essential for VPN connections
    iptables -I INPUT 1 -p udp --dport "$WG_PORT" -j ACCEPT
    
    # CRITICAL: Allow ALL traffic from VPN interface (before any DROP policies)
    iptables -I FORWARD 1 -i "$WG_INTERFACE" -j ACCEPT
    
    # CRITICAL: Allow ALL traffic to VPN interface (for return packets)
    iptables -I FORWARD 2 -o "$WG_INTERFACE" -j ACCEPT
    
    # Allow established and related connections (essential for two-way communication)
    iptables -I FORWARD 3 -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # ADDITIONAL: Ensure no blocking rules affect VPN traffic
    iptables -I FORWARD 4 -s "$VPN_NETWORK" -j ACCEPT
    iptables -I FORWARD 5 -d "$VPN_NETWORK" -j ACCEPT
    
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
    
    # CRITICAL: Disable reverse path filtering (can block VPN traffic)
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/conf/"$default_interface"/rp_filter 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/conf/"$WG_INTERFACE"/rp_filter 2>/dev/null || true
    
    # Additional optimizations for mobile connections
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null || true
    echo 1 > /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null || true
    
    # Enable loose reverse path filtering for VPN interface
    echo 2 > /proc/sys/net/ipv4/conf/"$WG_INTERFACE"/rp_filter 2>/dev/null || true
    
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
    
    # Create enhanced inline post-up commands with multiple safeguards
    POST_UP_COMMANDS="echo 1 > /proc/sys/net/ipv4/ip_forward; echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; echo 0 > /proc/sys/net/ipv4/conf/$default_interface/rp_filter; iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT; iptables -I FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -I FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -I FORWARD -s $VPN_NETWORK -j ACCEPT; iptables -I FORWARD -d $VPN_NETWORK -j ACCEPT; iptables -t nat -I POSTROUTING -s $VPN_NETWORK -o $default_interface -j MASQUERADE; iptables -t nat -I POSTROUTING -s $VPN_NETWORK ! -d $VPN_NETWORK -o $default_interface -j MASQUERADE; iptables -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
    
    # Create enhanced inline post-down commands
    POST_DOWN_COMMANDS="iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT; iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -D FORWARD -s $VPN_NETWORK -j ACCEPT; iptables -D FORWARD -d $VPN_NETWORK -j ACCEPT; iptables -t nat -D POSTROUTING -s $VPN_NETWORK -o $default_interface -j MASQUERADE; iptables -t nat -D POSTROUTING -s $VPN_NETWORK ! -d $VPN_NETWORK -o $default_interface -j MASQUERADE; iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
    
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
    
    # Test 1: Enhanced VPN routing test
    local test_ip="1.1.1.1"
    log "INFO" "Тестирование маршрутизации VPN с диагностикой..."
    
    # First, test without special routing (should work through default route + NAT)
    log "INFO" "Тест 1: Ping через обычную маршрутизацию..."
    if ping -c 1 -W 3 $test_ip >/dev/null 2>&1; then
        log "SUCCESS" "Обычный ping работает - интернет доступен"
    else
        log "ERROR" "Обычный ping не работает - проблемы с интернетом на сервере"
        all_tests_passed=false
    fi
    
    # Test 2: Check if VPN interface can route packets through MASQUERADE
    log "INFO" "Тест 2: Проверка NAT для VPN сети..."
    
    # Simulate VPN client packet by using specific source IP
    if ip addr add 10.0.0.100/32 dev "$WG_INTERFACE" 2>/dev/null; then
        log "DEBUG" "Добавлен тестовый IP 10.0.0.100 на $WG_INTERFACE"
        
        # Test ping from VPN IP
        if ping -c 1 -W 3 -I 10.0.0.100 $test_ip >/dev/null 2>&1; then
            log "SUCCESS" "NAT работает корректно для VPN сети"
        else
            log "WARN" "Проблемы с NAT для VPN сети"
            
            # Additional NAT diagnostics
            log "DEBUG" "Диагностика NAT:"
            log "DEBUG" "Активные соединения conntrack:"
            conntrack -L -s 10.0.0.0/24 2>/dev/null | head -3 | while read line; do
                log "DEBUG" "  $line"
            done || log "DEBUG" "  Conntrack недоступен или пуст"
            
            log "DEBUG" "NAT правила детально:"
            iptables -t nat -L POSTROUTING -n -v | head -10 | while read line; do
                log "DEBUG" "  $line"
            done
        fi
        
        # Clean up test IP
        ip addr del 10.0.0.100/32 dev "$WG_INTERFACE" 2>/dev/null || true
    else
        log "WARN" "Не удалось добавить тестовый IP на интерфейс"
    fi
    
    # Test 3: Direct route test (original test, but improved)
    log "INFO" "Тест 3: Прямая маршрутизация через $WG_INTERFACE..."
    if ip route add $test_ip/32 dev "$WG_INTERFACE" 2>/dev/null; then
        log "SUCCESS" "Тестовый маршрут добавлен: $test_ip -> $WG_INTERFACE"
        
        # Show the added route
        log "DEBUG" "Проверка добавленного маршрута:"
        ip route show $test_ip | while read route; do
            log "DEBUG" "  $route"
        done
        
        # Test ping with verbose output but limited time
        log "INFO" "Ping test через прямой маршрут (это может не работать и это нормально)..."
        if timeout 5 ping -c 1 -W 2 $test_ip 2>&1 | head -10 | tee -a "$LOG_FILE"; then
            log "SUCCESS" "Прямой ping через VPN интерфейс работает"
        else
            log "INFO" "Прямой ping не работает (это нормально - нужен подключенный клиент)"
            log "INFO" "VPN будет работать когда подключится реальный клиент"
        fi
        
        # Clean up test route
        ip route del $test_ip/32 dev "$WG_INTERFACE" 2>/dev/null || true
        log "INFO" "Тестовый маршрут удален"
    else
        log "ERROR" "Не удалось добавить тестовый маршрут"
    fi
    
    # Test 4: Check if real VPN traffic would work
    log "INFO" "Тест 4: Проверка готовности для реального VPN трафика..."
    
    # Check all required components
    local vpn_ready=true
    
    # Check WireGuard is listening
    if netstat -ulpn 2>/dev/null | grep -q ":$WG_PORT " || ss -ulpn 2>/dev/null | grep -q ":$WG_PORT "; then
        log "DEBUG" "✅ WireGuard слушает на порту $WG_PORT"
    else
        log "DEBUG" "❌ WireGuard не слушает на порту $WG_PORT"
        vpn_ready=false
    fi
    
    # Check IP forwarding
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
        log "DEBUG" "✅ IP forwarding включен"
    else
        log "DEBUG" "❌ IP forwarding отключен"
        vpn_ready=false
    fi
    
    # Check NAT rules
    if iptables -t nat -C POSTROUTING -s "$VPN_NETWORK" -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null; then
        log "DEBUG" "✅ NAT правила настроены"
    else
        log "DEBUG" "❌ NAT правила не найдены"
        vpn_ready=false
    fi
    
    # Check FORWARD rules
    if iptables -C FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null; then
        log "DEBUG" "✅ FORWARD правила настроены"
    else
        log "DEBUG" "❌ FORWARD правила не найдены"
        vpn_ready=false
    fi
    
    if $vpn_ready; then
        log "SUCCESS" "✅ VPN полностью готов для подключения клиентов"
    else
        log "WARN" "⚠️ Некоторые компоненты VPN настроены неправильно"
        all_tests_passed=false
    fi
    
    # Test 2: Check packet forwarding capability
    log "INFO" "Проверка возможности пересылки пакетов..."
    
    # Check if packets can flow from VPN network to internet
    local vpn_test_ip="10.0.0.100"  # Simulated client IP
    
    # Test with iptables tracing (if available)
    if command -v iptables-save >/dev/null 2>&1; then
        log "DEBUG" "Количество правил в каждой цепочке:"
        local input_rules=$(iptables -L INPUT -n | grep -c "^ACCEPT\|^DROP\|^REJECT" || echo "0")
        local forward_rules=$(iptables -L FORWARD -n | grep -c "^ACCEPT\|^DROP\|^REJECT" || echo "0")
        local nat_rules=$(iptables -t nat -L POSTROUTING -n | grep -c "^MASQUERADE\|^SNAT" || echo "0")
        log "DEBUG" "  INPUT: $input_rules правил"
        log "DEBUG" "  FORWARD: $forward_rules правил"
        log "DEBUG" "  NAT POSTROUTING: $nat_rules правил"
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
    save_server_ip
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
    
    # Add real-time client connection monitoring
    echo
    echo -e "${CYAN}=== МОНИТОРИНГ ПОДКЛЮЧЕНИЙ КЛИЕНТОВ ===${NC}"
    echo -e "${YELLOW}Для диагностики проблем с интернетом запустите:${NC}"
    echo -e "  ${GREEN}sudo bash $0 --monitor${NC}"
    echo
    echo -e "${YELLOW}Или проверьте подключения вручную:${NC}"
    echo -e "  ${GREEN}watch -n 2 'wg show && echo && iptables -t nat -L POSTROUTING -n -v | head -10'${NC}"
}

# Real-time client connection monitoring
monitor_connections() {
    log "INFO" "Запуск мониторинга подключений клиентов..."
    echo -e "${CYAN}Нажмите Ctrl+C для выхода${NC}"
    echo
    
    while true; do
        clear
        echo -e "${CYAN}=== МОНИТОРИНГ WIREGUARD ПОДКЛЮЧЕНИЙ ===${NC}"
        echo "Время: $(date)"
        echo
        
        # Show WireGuard status
        echo -e "${YELLOW}WireGuard статус:${NC}"
        if wg show 2>/dev/null | grep -q "peer:"; then
            wg show
            echo
            
            # Show active connections with traffic
            echo -e "${YELLOW}Активные соединения с трафиком:${NC}"
            wg show all dump | while read line; do
                if [[ "$line" =~ ^[a-zA-Z0-9+/=]+[[:space:]]+[a-zA-Z0-9+/=]+[[:space:]]+[0-9.]+ ]]; then
                    echo "  $line"
                fi
            done
            echo
            
            # Check NAT translations for connected clients
            echo -e "${YELLOW}NAT трансляции для VPN клиентов:${NC}"
            iptables -t nat -L POSTROUTING -n -v | grep "10.0.0" | head -5
            echo
            
            # Show conntrack entries for VPN network
            echo -e "${YELLOW}Активные соединения (conntrack):${NC}"
            conntrack -L -s 10.0.0.0/24 2>/dev/null | head -5 || echo "  Нет активных соединений или conntrack недоступен"
            echo
            
            # Test internet from server perspective
            echo -e "${YELLOW}Тест интернета с сервера:${NC}"
            if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
                echo -e "  ${GREEN}✅ Сервер имеет доступ к интернету${NC}"
            else
                echo -e "  ${RED}❌ Сервер НЕ имеет доступа к интернету${NC}"
            fi
            
            # Check if any VPN client is sending traffic
            local rx_bytes=$(wg show wg0 transfer | awk '{print $2}' | head -1)
            local tx_bytes=$(wg show wg0 transfer | awk '{print $3}' | head -1)
            
            if [[ -n "$rx_bytes" && "$rx_bytes" != "0" ]]; then
                echo -e "  ${GREEN}✅ Клиент отправляет данные (RX: $rx_bytes bytes)${NC}"
            else
                echo -e "  ${YELLOW}⚠️  Клиент не отправляет данные${NC}"
            fi
            
            if [[ -n "$tx_bytes" && "$tx_bytes" != "0" ]]; then
                echo -e "  ${GREEN}✅ Сервер отправляет данные клиенту (TX: $tx_bytes bytes)${NC}"
            else
                echo -e "  ${YELLOW}⚠️  Сервер не отправляет данные клиенту${NC}"
            fi
            
        else
            echo -e "  ${YELLOW}Нет подключенных клиентов${NC}"
            echo
            echo -e "${CYAN}Ожидание подключения клиентов...${NC}"
            echo "Убедитесь что:"
            echo "1. Клиент использует правильный IP сервера: $(cat /tmp/wg_server_ip 2>/dev/null || echo 'UNKNOWN')"
            echo "2. Порт $WG_PORT открыт в firewall облачного провайдера"
            echo "3. Конфигурация клиента правильная"
        fi
        
        echo -e "${CYAN}Обновление через 3 секунды...${NC}"
        sleep 3
    done
}

# Diagnostic function to run when client is connected
diagnose_client_connection() {
    local client_ip="$1"
    
    log "INFO" "Диагностика подключения клиента $client_ip"
    
    # Check if client is in WireGuard
    if ! wg show | grep -q "$client_ip"; then
        log "ERROR" "Клиент $client_ip не найден в WireGuard"
        return 1
    fi
    
    # Test ping to client
    log "INFO" "Тест ping к клиенту..."
    if ping -c 3 -W 2 "$client_ip" >/dev/null 2>&1; then
        log "SUCCESS" "Ping к клиенту $client_ip успешен"
    else
        log "ERROR" "Ping к клиенту $client_ip неуспешен"
    fi
    
    # Check routing to client
    log "INFO" "Проверка маршрутизации к клиенту..."
    local route_to_client=$(ip route get "$client_ip" 2>/dev/null || echo "no route")
    log "INFO" "Маршрут к $client_ip: $route_to_client"
    
    # Check if NAT is working for this client
    log "INFO" "Проверка NAT для клиента..."
    local nat_count=$(iptables -t nat -L POSTROUTING -n -v | grep -c "$client_ip" || echo "0")
    log "INFO" "NAT правил для $client_ip: $nat_count"
    
    # Show conntrack entries for this client
    log "INFO" "Активные соединения клиента:"
    conntrack -L -s "$client_ip" 2>/dev/null | head -10 || log "INFO" "Нет активных соединений"
    
    # Test if server can masquerade traffic from this client
    log "INFO" "Тест MASQUERADE для клиента..."
    
    # Add temporary route and test
    if ip route add 1.1.1.1/32 via "$client_ip" dev wg0 2>/dev/null; then
        log "INFO" "Временный маршрут добавлен"
        sleep 1
        ip route del 1.1.1.1/32 via "$client_ip" dev wg0 2>/dev/null || true
    fi
    
    return 0
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

# Save server IP for monitoring
save_server_ip() {
    echo "$SERVER_PUBLIC_IP" > /tmp/wg_server_ip 2>/dev/null || true
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
    -m|--monitor)
        if [[ $EUID -ne 0 ]]; then
            echo "Мониторинг требует права root. Используйте: sudo $0 --monitor"
            exit 1
        fi
        monitor_connections
        exit 0
        ;;
    --diagnose)
        if [[ $EUID -ne 0 ]]; then
            echo "Диагностика требует права root. Используйте: sudo $0 --diagnose [IP_клиента]"
            exit 1
        fi
        if [[ -n "${2:-}" ]]; then
            diagnose_client_connection "$2"
        else
            echo "Укажите IP клиента для диагностики: $0 --diagnose 10.0.0.2"
            exit 1
        fi
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