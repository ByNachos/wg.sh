# 🚀 WireGuard - Быстрый старт

Универсальный скрипт для автоматической установки VPN сервера за 3 команды.

## 🎯 Краткая инструкция

### 1. Запуск на сервере
```bash
curl -O https://raw.githubusercontent.com/your-repo/wg.sh/main/wg-universal-setup.sh
chmod +x wg-universal-setup.sh
sudo ./wg-universal-setup.sh
```

### 2. Следуйте инструкциям скрипта
- Укажите количество клиентов (по умолчанию: 3)
- Дайте имена клиентам (client1, client2, client3...)
- Дождитесь завершения установки

### 3. Настройте клиентов
```bash
# Узнайте IP сервера
curl ifconfig.me

# Замените SERVER_IP в конфигурациях
sed -i 's/SERVER_IP/ВАШ_IP/g' /etc/wireguard/clients/*.conf

# Посмотрите готовые конфигурации
ls -la /etc/wireguard/clients/
```

## 📱 Подключение клиентов

### Мобильные (Android/iOS)
1. Установите приложение WireGuard
2. Нажмите "+" → "Создать из файла"
3. Импортируйте файл из `/etc/wireguard/clients/`

### Компьютеры
1. Установите WireGuard с официального сайта
2. Импортируйте конфигурацию

## ✅ Проверка работы

```bash
# Статус сервера
sudo wg show

# Логи
sudo journalctl -u wg-quick@wg0 -f
```

## 🔧 Управление

```bash
# Перезапуск
sudo systemctl restart wg-quick@wg0

# Остановка
sudo systemctl stop wg-quick@wg0

# Автозапуск включен автоматически
```

---

**Готово!** Ваш VPN работает с оптимальными настройками для всех устройств.