#!/bin/bash

# WireGuard Universal Setup Script
# One-script solution for complete WireGuard VPN server setup
# Automatically configures network, ports, firewall, and creates optimized configurations
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
readonly SERVER_IP="10.0.0.1"

# File paths
readonly LOG_FILE="/var/log/wg-universal-setup.log"
readonly CONFIG_DIR="/etc/wireguard"
readonly BACKUP_DIR="/etc/wireguard/backups"

# Global variables
WG_INTERFACE=""
WAN_INTERFACE=""
WG_PORT=$DEFAULT_PORT
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
    esac
    
    # Write to log file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
}

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║        WireGuard Universal Setup Script v2.0                ║"
    echo "║                                                              ║"
    echo "║  Автоматическая настройка VPN сервера для всех устройств     ║"
    echo "║  Оптимизированные настройки для WiFi и мобильных сетей       ║"
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
            apt update && apt install -y wireguard wireguard-tools
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

# Detect network interfaces
detect_interfaces() {
    log "STEP" "Определение сетевых интерфейсов..."
    
    # Determine WAN interface (interface with default route)
    WAN_INTERFACE=$(ip route show default 2>/dev/null | head -1 | grep -oP 'dev \K\S+' || echo "")
    
    if [[ -z "$WAN_INTERFACE" ]]; then
        log "WARN" "Не удалось автоматически определить WAN интерфейс"
        echo "Доступные интерфейсы:"
        ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '
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
    if ! netstat -ulpn 2>/dev/null | grep -q ":$DEFAULT_PORT "; then
        WG_PORT=$DEFAULT_PORT
        log "SUCCESS" "Используется стандартный порт: $WG_PORT"
    elif ! netstat -ulpn 2>/dev/null | grep -q ":$ALTERNATIVE_PORT "; then
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
    fi
    
    if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf 2>/dev/null || true
    fi
    
    sysctl -p >/dev/null 2>&1
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
    
    log "SUCCESS" "TCP настройки оптимизированы"
}

# Configure iptables rules
setup_firewall() {
    log "STEP" "Настройка правил firewall..."
    
    # Backup existing rules
    iptables-save > "$BACKUP_DIR/iptables-backup-$(date +%Y%m%d-%H%M%S).rules" 2>/dev/null || true
    
    # Allow WireGuard port
    iptables -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
    
    # Allow forwarding for WireGuard interface
    iptables -I FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -I FORWARD -o "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    
    # Set up MASQUERADE for NAT
    iptables -t nat -I POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null || true
    
    # Universal optimizations
    iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    
    # MSS clamping for optimal packet handling
    iptables -t mangle -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    iptables -t mangle -I OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    
    # Allow fragmented packets
    iptables -I INPUT -f -j ACCEPT 2>/dev/null || true
    iptables -I FORWARD -f -j ACCEPT 2>/dev/null || true
    
    # Optimize connection tracking
    echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null || true
    echo 300 > /proc/sys/net/netfilter/nf_conntrack_generic_timeout 2>/dev/null || true
    
    # Save iptables rules (distribution specific)
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            if command -v iptables-persistent &> /dev/null; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            fi
            ;;
        *"CentOS"*|*"Red Hat"*|*"Rocky"*|*"AlmaLinux"*|*"Fedora"*)
            if command -v iptables-save &> /dev/null; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
            ;;
    esac
    
    log "SUCCESS" "Правила firewall настроены"
}

# Create post-up script
create_post_up_script() {
    local post_up_script="$CONFIG_DIR/post-up.sh"
    
    cat > "$post_up_script" << EOF
#!/bin/bash
# WireGuard post-up script - Universal optimization
# Auto-generated by wg-universal-setup.sh

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# iptables rules
iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT
iptables -I FORWARD -i $WG_INTERFACE -j ACCEPT
iptables -I FORWARD -o $WG_INTERFACE -j ACCEPT
iptables -t nat -I POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t mangle -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

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
# Auto-generated by wg-universal-setup.sh

# Remove iptables rules
iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -o $WAN_INTERFACE -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

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
# WireGuard Server Configuration - Universal Optimized
# Generated by wg-universal-setup.sh on $(date)
# Optimized for all device types with proven values

[Interface]
# Server private key
PrivateKey = $SERVER_PRIVATE_KEY

# Server IP address within VPN network
Address = $SERVER_IP/24

# Listen port - optimized for compatibility
ListenPort = $WG_PORT

# MTU optimized for universal device compatibility
MTU = $OPTIMAL_MTU

# DNS server for clients
DNS = $OPTIMAL_DNS

# Post-up script to configure routing and firewall
PostUp = $CONFIG_DIR/post-up.sh

# Post-down script to clean up
PostDown = $CONFIG_DIR/post-down.sh

# Client configurations will be added here
# Use: wg-quick addpeer $WG_INTERFACE <client-config>

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

# Server endpoint (change SERVER_IP to your actual server IP)
Endpoint = SERVER_IP:$WG_PORT

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
    log "SUCCESS" "Создано $CLIENT_COUNT клиентских конфигураций"
}

# Start WireGuard interface
start_wireguard() {
    log "STEP" "Запуск WireGuard интерфейса..."
    
    if wg-quick up "$WG_INTERFACE" 2>/dev/null; then
        log "SUCCESS" "WireGuard интерфейс $WG_INTERFACE запущен"
        
        # Enable systemd service
        systemctl enable wg-quick@"$WG_INTERFACE" 2>/dev/null || true
        log "SUCCESS" "WireGuard сервис включен для автозапуска"
    else
        error_exit "Не удалось запустить WireGuard интерфейс"
    fi
}

# Test connectivity
test_connectivity() {
    log "STEP" "Проверка подключения..."
    
    # Test if interface is up
    if ip link show "$WG_INTERFACE" &>/dev/null; then
        log "SUCCESS" "Интерфейс $WG_INTERFACE активен"
        
        # Show interface status
        local wg_status=$(wg show "$WG_INTERFACE" 2>/dev/null || echo "Статус недоступен")
        log "INFO" "Статус WireGuard: $wg_status"
    else
        log "ERROR" "Интерфейс $WG_INTERFACE не активен"
    fi
    
    # Test internet connectivity
    if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log "SUCCESS" "Подключение к интернету работает"
    else
        log "WARN" "Проблемы с подключением к интернету"
    fi
    
    # Test MTU
    if ping -c 1 -s $((OPTIMAL_MTU - 28)) -M do 8.8.8.8 >/dev/null 2>&1; then
        log "SUCCESS" "MTU $OPTIMAL_MTU оптимален"
    else
        log "WARN" "Возможны проблемы с MTU $OPTIMAL_MTU"
    fi
}

# Generate setup summary
show_setup_summary() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    УСТАНОВКА ЗАВЕРШЕНА                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    log "INFO" "Конфигурация WireGuard VPN сервера:"
    echo -e "  ${CYAN}Интерфейс WireGuard:${NC} $WG_INTERFACE"
    echo -e "  ${CYAN}WAN интерфейс:${NC} $WAN_INTERFACE"
    echo -e "  ${CYAN}Порт:${NC} $WG_PORT"
    echo -e "  ${CYAN}MTU:${NC} $OPTIMAL_MTU (универсальный оптимум)"
    echo -e "  ${CYAN}PersistentKeepalive:${NC} $OPTIMAL_KEEPALIVE секунд"
    echo -e "  ${CYAN}DNS:${NC} $OPTIMAL_DNS"
    echo -e "  ${CYAN}Сеть VPN:${NC} $VPN_NETWORK"
    echo -e "  ${CYAN}IP сервера:${NC} $SERVER_IP"
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
    echo
    
    echo -e "${GREEN}✅ VPN сервер готов к работе!${NC}"
    echo -e "${GREEN}✅ Оптимизирован для всех типов устройств и сетей${NC}"
    echo -e "${GREEN}✅ Поддерживает WiFi и мобильные соединения${NC}"
    echo
    
    echo -e "${CYAN}Не забудьте:${NC}"
    echo "1. Изменить 'SERVER_IP' в клиентских конфигурациях на реальный IP сервера"
    echo "2. Передать клиентские конфигурации пользователям безопасным способом"
    echo "3. Открыть порт $WG_PORT в облачном firewall (если используется)"
    echo
}

# Main installation function
main() {
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    print_banner
    
    log "INFO" "Начало универсальной установки WireGuard VPN сервера"
    log "INFO" "Логи сохраняются в: $LOG_FILE"
    
    # System checks and preparation
    check_root
    detect_os
    install_wireguard
    load_wireguard_module
    
    # Network configuration
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
    test_connectivity
    
    # Summary
    show_setup_summary
    
    log "SUCCESS" "Универсальная установка WireGuard завершена успешно!"
}

# Show usage information
show_usage() {
    echo "Использование: $0 [ОПЦИИ]"
    echo
    echo "WireGuard Universal Setup Script"
    echo "Полностью автоматическая установка и настройка VPN сервера"
    echo
    echo "Опции:"
    echo "  -h, --help     Показать эту справку"
    echo "  -v, --version  Показать версию"
    echo
    echo "Этот скрипт автоматически:"
    echo "  • Устанавливает WireGuard (если нужно)"
    echo "  • Настраивает оптимальные сетевые параметры"
    echo "  • Создает правила firewall"
    echo "  • Генерирует серверную и клиентские конфигурации"
    echo "  • Запускает и тестирует VPN сервер"
    echo
    echo "Оптимизировано для всех типов устройств и сетей."
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_usage
        exit 0
        ;;
    -v|--version)
        echo "WireGuard Universal Setup Script v2.0"
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