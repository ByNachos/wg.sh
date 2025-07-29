# [QUICK] WireGuard CLI - Быстрый старт

Профессиональный CLI инструмент для управления WireGuard VPN серверами.

## [MAIN] Краткая инструкция

### 1. Установка CLI
```bash
curl -O https://raw.githubusercontent.com/your-repo/wg.sh/main/wg-cli.sh
chmod +x wg-cli.sh
```

### 2. Установка VPN сервера  
```bash
sudo ./wg-cli.sh setup
```

### 3. Проверка и управление
```bash
# Проверить статус
./wg-cli.sh status

# Посмотреть клиентские конфигурации
./wg-cli.sh clients list

# Мониторинг подключений
sudo ./wg-cli.sh monitor
```

## [MOBILE] Подключение клиентов

### Мобильные (Android/iOS)
1. Установите приложение WireGuard
2. Нажмите "+" → "Создать из файла"
3. Импортируйте файл из `/etc/wireguard/clients/`

### Компьютеры
1. Установите WireGuard с официального сайта
2. Импортируйте конфигурацию

## [OK] Проверка работы

```bash
# Статус через CLI
./wg-cli.sh status

# Диагностика проблем
sudo ./wg-cli.sh diagnose

# Автоисправление
sudo ./wg-cli.sh diagnose --fix
```

## [MANAGE] Управление

```bash
# Добавить клиента
./wg-cli.sh clients add имя_клиента

# Удалить клиента  
./wg-cli.sh clients remove имя_клиента

# Показать конфигурацию
./wg-cli.sh config show

# Справка по командам
./wg-cli.sh help
```

---

**Готово!** Ваш VPN работает с оптимальными настройками для всех устройств.