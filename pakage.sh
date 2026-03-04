#!/bin/bash

# Tạo thư mục log và backup
mkdir -p /root/security-monitor
mkdir -p /root/security-backup

# Backup các file cấu hình hiện tại
backup_configs() {
    echo "Backing up current configurations..."
    BACKUP_DIR="/root/security-backup/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup các file cấu hình quan trọng
    cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null
    cp /etc/nftables.conf "$BACKUP_DIR/" 2>/dev/null
    cp /etc/fail2ban/jail.local "$BACKUP_DIR/" 2>/dev/null
    cp /etc/suricata/threshold.config "$BACKUP_DIR/" 2>/dev/null
    
    echo "Backup completed to $BACKUP_DIR"
}

# Kiểm tra xem một gói đã được cài đặt chưa
check_package() {
    if ! dpkg -l | grep -q "^ii  $1"; then
        echo "Installing $1..."
        apt install -y "$1" || {
            echo "Failed to install $1. Exiting."
            exit 1
        }
    else
        echo "$1 is already installed."
    fi
}

# Kiểm tra môi trường
check_environment() {
    # Kiểm tra OS
    if [ ! -f /etc/debian_version ]; then
        echo "This script is designed for Debian/Ubuntu systems only."
        exit 1
    fi
    
    # Kiểm tra quyền root
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1
    fi
    
    # Kiểm tra phiên bản kernel
    KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
    if (( $(echo "$KERNEL_VERSION < 4.9" | bc -l) )); then
        echo "Warning: This script works best with kernel 4.9 or newer."
        echo "Current kernel version: $(uname -r)"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Cập nhật hệ thống
update_system() {
    echo "Updating system packages..."
    apt update || {
        echo "Failed to update package lists. Exiting."
        exit 1
    }
    
    apt upgrade -y || {
        echo "Failed to upgrade packages. Exiting."
        exit 1
    }
}

# Cài đặt các gói cần thiết
install_packages() {
    echo "Installing security packages..."
    
    # Danh sách các gói cần thiết
    PACKAGES=(
        "fail2ban"
        "vnstat"
        "libapache2-mod-evasive"
        "libapache2-mod-security2"
        "net-tools"
        "tcpdump"
        "nftables"
        "psad"
        "rkhunter"
        "lynis"
        "aide"
        "suricata"
        "htop"
        "iftop"
        "bc"
        "mailutils"
    )
    
    for package in "${PACKAGES[@]}"; do
        check_package "$package"
    done
}

# Cấu hình kernel
configure_kernel() {
    echo "Configuring kernel security parameters..."
    
    # Backup sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    
    cat <<EOF > /etc/sysctl.conf
# Bảo vệ chống SYN flood và DDoS
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0

# TCP optimizations
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=15
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1

# ICMP protection
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_ratelimit=100
net.ipv4.icmp_echo_ignore_all=0

# IP spoofing protection
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.log_martians=1

# Performance optimizations
net.core.netdev_max_backlog=65536
net.core.somaxconn=65536
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_mtu_probing=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 87380 16777216

# Use BBR congestion control if available
net.ipv4.tcp_congestion_control=bbr
EOF

    # Áp dụng cấu hình
    if sysctl -p; then
        echo "Kernel parameters applied successfully."
    else
        echo "Failed to apply some kernel parameters. Check /etc/sysctl.conf for compatibility."
        # Khôi phục cấu hình gốc nếu lỗi
        cp /etc/sysctl.conf.bak /etc/sysctl.conf
    fi
}

# Cấu hình nftables
configure_nftables() {
    echo "Configuring nftables firewall..."
    
    # Tạo file cấu hình nftables
    cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    # Định nghĩa các sets
    set whitelist {
        type ipv4_addr
        elements = { 127.0.0.1 }
    }
    
    set blacklist {
        type ipv4_addr
    }
    
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Whitelist
        ip saddr @whitelist accept
        
        # Blacklist
        ip saddr @blacklist drop
        
        # Accept established connections
        ct state established,related accept
        
        # Accept loopback
        iifname lo accept
        
        # ICMP/ICMPv6 rate limiting
        ip protocol icmp limit rate 10/second accept
        ip6 nexthdr icmpv6 limit rate 10/second accept
        
        # SSH rate limiting
        tcp dport 22 ct state new limit rate 10/minute accept
        
        # HTTP(S) DDoS protection
        tcp dport {80, 443} ct state new limit rate 100/second accept
        
        # Drop invalid packets
        ct state invalid drop
        
        # Drop fragments
        ip frag-off & 0x1fff != 0 drop
        
        # Drop XMAS packets
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) drop
        
        # Drop null packets
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        
        # Drop uncommon MSS values
        tcp flags syn tcp option maxseg size 1-536 drop
        
        # Log dropped packets
        limit rate 5/minute log prefix "nftables dropped: " flags all
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

    # Tạo file whitelist và blacklist
    touch /root/security-monitor/whitelist.txt
    touch /root/security-monitor/blacklist.txt
    
    # Kích hoạt nftables
    systemctl enable nftables
    systemctl restart nftables || {
        echo "Failed to start nftables. Check configuration."
        exit 1
    }
}

# Cấu hình suricata
configure_suricata() {
    echo "Configuring Suricata IDS/IPS..."
    
    # Kiểm tra xem suricata đã được cài đặt chưa
    if ! command -v suricata &> /dev/null; then
        echo "Suricata is not installed. Skipping configuration."
        return
    fi
    
    # Cấu hình threshold
    cat <<EOF > /etc/suricata/threshold.config
# Giới hạn cảnh báo cho các rule
threshold gen id 1, type threshold, track by_src, count 5, seconds 60
threshold gen id 2, type threshold, track by_dst, count 5, seconds 60
EOF

    # Khởi động lại suricata
    systemctl enable suricata
    systemctl restart suricata || {
        echo "Failed to start Suricata. Check configuration."
    }
}

# Cấu hình fail2ban
configure_fail2ban() {
    echo "Configuring fail2ban..."
    
    # Kiểm tra xem fail2ban đã được cài đặt chưa
    if ! command -v fail2ban-client &> /dev/null; then
        echo "fail2ban is not installed. Skipping configuration."
        return
    fi
    
    cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 3
banaction = nftables-multiport
chain = input

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[apache-ddos]
enabled = true
port = http,https
filter = apache-ddos
logpath = /var/log/apache2/access.log
maxretry = 300
findtime = 300
bantime = 600

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache2/access.log
maxretry = 2

[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/apache2/access.log
maxretry = 5

[apache-overflows]
enabled = true
port = http,https
filter = apache-overflows
logpath = /var/log/apache2/access.log
maxretry = 2
EOF

    # Khởi động lại fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban || {
        echo "Failed to start fail2ban. Check configuration."
    }
}

# Tạo script giám sát
create_monitor_script() {
    echo "Creating monitoring script..."
    
    cat <<EOF > /root/security-monitor/monitor.sh
#!/bin/bash

# Config file
CONFIG_FILE="/root/security-monitor/config.json"

# Tạo file config nếu chưa tồn tại
if [ ! -f "\$CONFIG_FILE" ]; then
    cat <<CONFIG > "\$CONFIG_FILE"
{
    "thresholds": {
        "connections": $(nproc --all)00,
        "bandwidth_mb": 1000,
        "cpu_percent": 80,
        "mem_percent": 80,
        "iowait_percent": 20
    },
    "email": "admin@yourdomain.com",
    "alert_cooldown": 300,
    "network_interface": "$(ip route | grep default | awk '{print $5}')",
    "log_rotation_days": 7
}
CONFIG
fi

# Đọc cấu hình
CONNECTIONS_THRESHOLD=\$(grep -o '"connections": [0-9]*' "\$CONFIG_FILE" | awk '{print \$2}')
BANDWIDTH_THRESHOLD=\$(grep -o '"bandwidth_mb": [0-9]*' "\$CONFIG_FILE" | awk '{print \$2}')
CPU_THRESHOLD=\$(grep -o '"cpu_percent": [0-9]*' "\$CONFIG_FILE" | awk '{print \$2}')
MEM_THRESHOLD=\$(grep -o '"mem_percent": [0-9]*' "\$CONFIG_FILE" | awk '{print \$2}')
IOWAIT_THRESHOLD=\$(grep -o '"iowait_percent": [0-9]*' "\$CONFIG_FILE" | awk '{print \$2}')
ADMIN_EMAIL=\$(grep -o '"email": "[^"]*' "\$CONFIG_FILE" | awk -F'"' '{print \$4}')
ALERT_COOLDOWN=\$(grep -o '"alert_cooldown": [0-9]*' "\$CONFIG_FILE" | awk '{print \$2}')
NETWORK_INTERFACE=\$(grep -o '"network_interface": "[^"]*' "\$CONFIG_FILE" | awk -F'"' '{print \$4}')
LOG_ROTATE_DAYS=\$(grep -o '"log_rotation_days": [0-9]*' "\$CONFIG_FILE" | awk '{print \$2}')

# Thư mục log
LOG_DIR="/root/security-monitor/logs"
mkdir -p "\$LOG_DIR"

# File log chính
LOG_FILE="\$LOG_DIR/security-monitor-\$(date +%Y%m%d).log"
ALERT_HISTORY="\$LOG_DIR/alert-history.log"

# Hàm ghi log
log_message() {
    local level=\$1
    local message=\$2
    echo "\$(date +'%Y-%m-%d %H:%M:%S') [\$level] \$message" >> "\$LOG_FILE"
    echo "\$(date +'%Y-%m-%d %H:%M:%S') [\$level] \$message"
}

# Hàm gửi cảnh báo
    send_alert() {
        local metric=$1
        local value=$2
        local threshold=$3
        
        # Kiểm tra thời gian cooldown
        if [ -f "$ALERT_HISTORY" ]; then
            last_alert=$(grep "$metric" "$ALERT_HISTORY" | tail -1)
            if [ ! -z "$last_alert" ]; then
                last_time=$(echo "$last_alert" | awk '{print $1 " " $2}')
                current_time=$(date +'%Y-%m-%d %H:%M:%S')
                
                # Tính thời gian đã trôi qua (giây)
                time_diff=$(( $(date -d "$current_time" +%s) - $(date -d "$last_time" +%s) ))
                
                # Bỏ qua nếu chưa hết thời gian cooldown
                if [ $time_diff -lt $ALERT_COOLDOWN ]; then
                    log_message "INFO" "Alert for $metric suppressed (cooldown: $time_diff < $ALERT_COOLDOWN seconds)"
                    return
                fi
            fi
        fi
        
        # Ghi nhật ký cảnh báo
        echo "$(date +'%Y-%m-%d %H:%M:%S') $metric $value $threshold" >> "$ALERT_HISTORY"
        
        # Tạo nội dung email
        local subject="[SERVER ALERT] $metric Threshold Exceeded"
        local body="
Security Alert from $(hostname) - $(date)

Metric: $metric
Current Value: $value
Threshold: $threshold

Server Details:
- Hostname: $(hostname)
- IP: $(hostname -I | awk '{print $1}')
- Load Average: $(uptime | awk -F'load average:' '{print $2}')
- Memory Usage: $(free -m | grep Mem | awk '{print $3"/"$2" MB"}')
- Disk Usage: $(df -h / | tail -1 | awk '{print $5}')

This is an automated message. Please check the server.
"
        
        # Gửi email
        if command -v mail &> /dev/null; then
            echo "$body" | mail -s "$subject" "$ADMIN_EMAIL"
            log_message "ALERT" "Email alert sent for $metric ($value > $threshold)"
        else
            log_message "ERROR" "Cannot send email - mail command not found"
        fi
        
        # Thực hiện hành động phản ứng
        case "$metric" in
            "CONNECTIONS")
                handle_high_connections "$value"
                ;;
            "BANDWIDTH")
                handle_high_bandwidth "$value"
                ;;
            "CPU")
                handle_high_cpu "$value"
                ;;
            "MEMORY")
                handle_high_memory "$value"
                ;;
        esac
    }

    # Xử lý connections cao
    handle_high_connections() {
        log_message "ACTION" "Handling high connections: $1"
        
        # Kiểm tra và khởi động lại apache nếu cần
        if systemctl is-active --quiet apache2; then
            systemctl restart apache2
            log_message "ACTION" "Restarted Apache"
        fi
        
        # Thêm rule giới hạn kết nối
        nft add rule inet filter input tcp dport 80 limit rate 50/second 2>/dev/null
        log_message "ACTION" "Added connection rate limiting rule"
    }

    # Xử lý bandwidth cao
    handle_high_bandwidth() {
        log_message "ACTION" "Handling high bandwidth: $1"
        
        # Kiểm tra và thêm giới hạn băng thông
        tc qdisc del dev $NETWORK_INTERFACE root 2>/dev/null
        tc qdisc add dev $NETWORK_INTERFACE root tbf rate 10mbit burst 32kbit latency 400ms
        log_message "ACTION" "Added bandwidth limiting rule"
    }

    # Xử lý CPU cao
    handle_high_cpu() {
        log_message "ACTION" "Handling high CPU: $1"
        
        # Tìm và giảm priority của các process sử dụng nhiều CPU
        for pid in $(ps aux | awk -v threshold=$CPU_THRESHOLD '$3 > threshold {print $2}'); do
            process_name=$(ps -p $pid -o comm=)
            # Bỏ qua các process hệ thống quan trọng
            if ! echo "$process_name" | grep -qE '^(init|systemd|kernel|kthread|watchdog|migration)'; then
                # Giảm priority thay vì kill
                renice +10 -p $pid 2>/dev/null
                log_message "ACTION" "Reduced priority of high CPU process: $process_name ($pid)"
            fi
        done
    }

    # Xử lý memory cao
    handle_high_memory() {
        log_message "ACTION" "Handling high memory: $1"
        
        # Dọn cache
        sync
        echo 3 > /proc/sys/vm/drop_caches
        log_message "ACTION" "Cleared cache"
    }

    # Đánh giá và cập nhật blacklist
    update_blacklist() {
        log_message "INFO" "Updating blacklist"
        
        # Tìm các IP đáng ngờ từ log
        for ip in $(grep "Invalid user" /var/log/auth.log 2>/dev/null | awk '{print $10}' | sort | uniq -c | sort -nr | head -n 10 | awk '{print $2}'); do
            # Kiểm tra IP trong whitelist
            if grep -q "$ip" /root/security-monitor/whitelist.txt; then
                log_message "INFO" "IP $ip is whitelisted, skipping"
                continue
            fi
            
            # Kiểm tra IP trong blacklist
            if ! grep -q "$ip" /root/security-monitor/blacklist.txt; then
                echo "$ip" >> /root/security-monitor/blacklist.txt
                log_message "ACTION" "Added $ip to blacklist"
                
                # Cập nhật nftables
                nft add element inet filter blacklist { $ip } 2>/dev/null
            fi
        done
    }

    # Kiểm tra log rotation
    rotate_logs() {
        # Xóa các file log cũ
        find "$LOG_DIR" -name "security-monitor-*.log" -type f -mtime +$LOG_ROTATE_DAYS -delete
        
        # Làm gọn file history
        if [ -f "$ALERT_HISTORY" ] && [ $(wc -l < "$ALERT_HISTORY") -gt 1000 ]; then
            tail -n 1000 "$ALERT_HISTORY" > "$ALERT_HISTORY.tmp"
            mv "$ALERT_HISTORY.tmp" "$ALERT_HISTORY"
        fi
    }

    # Chính: Kiểm tra và phản ứng
    main() {
        log_message "INFO" "Starting security monitoring scan"
        
        # Kiểm tra và xoay vòng log
        rotate_logs
        
        # Kiểm tra connections
        if command -v netstat &> /dev/null; then
            CONNECTIONS=$(netstat -ant | grep -E ":(80|443)" | wc -l)
            log_message "INFO" "Current connections: $CONNECTIONS (threshold: $CONNECTIONS_THRESHOLD)"
            
            if [ $CONNECTIONS -gt $CONNECTIONS_THRESHOLD ]; then
                send_alert "CONNECTIONS" $CONNECTIONS $CONNECTIONS_THRESHOLD
            fi
        fi
        
        # Kiểm tra bandwidth (chỉ khi vnstat đã thu thập đủ dữ liệu)
        if command -v vnstat &> /dev/null && vnstat --version &>/dev/null; then
            # Sử dụng phương pháp khác để đo băng thông
            if [ -f "/sys/class/net/$NETWORK_INTERFACE/statistics/rx_bytes" ]; then
                RX_BYTES_START=$(cat /sys/class/net/$NETWORK_INTERFACE/statistics/rx_bytes)
                TX_BYTES_START=$(cat /sys/class/net/$NETWORK_INTERFACE/statistics/tx_bytes)
                
                # Đợi 5 giây để đo
                sleep 5
                
                RX_BYTES_END=$(cat /sys/class/net/$NETWORK_INTERFACE/statistics/rx_bytes)
                TX_BYTES_END=$(cat /sys/class/net/$NETWORK_INTERFACE/statistics/tx_bytes)
                
                # Tính toán MB/s
                RX_MB_SEC=$(echo "scale=2; ($RX_BYTES_END - $RX_BYTES_START) / 1024 / 1024 / 5" | bc)
                TX_MB_SEC=$(echo "scale=2; ($TX_BYTES_END - $TX_BYTES_START) / 1024 / 1024 / 5" | bc)
                TOTAL_MB_SEC=$(echo "$RX_MB_SEC + $TX_MB_SEC" | bc)
                
                # Chuyển đổi sang MB/h để so sánh với ngưỡng
                BANDWIDTH_USAGE=$(echo "$TOTAL_MB_SEC * 3600" | bc | cut -d. -f1)
                
                log_message "INFO" "Current bandwidth: $BANDWIDTH_USAGE MB/h (threshold: $BANDWIDTH_THRESHOLD)"
                
                if [ $BANDWIDTH_USAGE -gt $BANDWIDTH_THRESHOLD ]; then
                    send_alert "BANDWIDTH" $BANDWIDTH_USAGE $BANDWIDTH_THRESHOLD
                fi
            fi
        fi
        
        # Kiểm tra CPU
        CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | cut -d. -f1)
        log_message "INFO" "Current CPU usage: $CPU_USAGE% (threshold: $CPU_THRESHOLD%)"
        
        if [ $CPU_USAGE -gt $CPU_THRESHOLD ]; then
            send_alert "CPU" $CPU_USAGE $CPU_THRESHOLD
        fi
        
        # Kiểm tra Memory
        MEM_USAGE=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
        log_message "INFO" "Current memory usage: $MEM_USAGE% (threshold: $MEM_THRESHOLD%)"
        
        if [ $MEM_USAGE -gt $MEM_THRESHOLD ]; then
            send_alert "MEMORY" $MEM_USAGE $MEM_THRESHOLD
        fi
        
        # Cập nhật blacklist
        update_blacklist
        
        # Tạo báo cáo
        cat <<REPORT > /root/security-monitor/report.txt
=== Báo cáo Bảo mật ===
Thời gian: $(date)
Hostname: $(hostname)
IP: $(hostname -I | awk '{print $1}')

--- Tài nguyên ---
Connections: $CONNECTIONS/$CONNECTIONS_THRESHOLD
Bandwidth: $BANDWIDTH_USAGE/$BANDWIDTH_THRESHOLD MB/h
CPU Usage: $CPU_USAGE%/$CPU_THRESHOLD%
Memory Usage: $MEM_USAGE%/$MEM_THRESHOLD%

--- Bảo mật ---
Số IP bị chặn: $(wc -l < /root/security-monitor/blacklist.txt)
Số cảnh báo gần đây: $(grep "$(date +%Y-%m-%d)" "$ALERT_HISTORY" 2>/dev/null | wc -l)

--- Trạng thái dịch vụ ---
fail2ban: $(systemctl is-active fail2ban)
nftables: $(systemctl is-active nftables)
suricata: $(systemctl is-active suricata)
REPORT
        
        log_message "INFO" "Completed security monitoring scan"
    }

    # Chạy chương trình chính
    main
EOF

# Tạo script phản ứng
cat <<EOF > /root/security-monitor/update-blacklist.sh
#!/bin/bash
# Script cập nhật blacklist từ các nguồn uy tín

# Tải blacklist từ các nguồn uy tín
wget -qO- https://www.blocklist.de/downloads/export-ips_all.txt | grep -v "#" >> /tmp/blacklist.tmp
wget -qO- https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset | grep -v "#" >> /tmp/blacklist.tmp

# Lọc và thêm vào blacklist
sort /tmp/blacklist.tmp | uniq > /tmp/blacklist_sorted.tmp

# Kiểm tra whitelist
while read ip; do
    if ! grep -q "\$ip" /root/security-monitor/whitelist.txt; then
        echo "\$ip" >> /root/security-monitor/blacklist.txt
    fi
done < /tmp/blacklist_sorted.tmp

# Xóa file tạm
rm /tmp/blacklist.tmp /tmp/blacklist_sorted.tmp

# Cập nhật nftables
nft flush set inet filter blacklist
cat /root/security-monitor/blacklist.txt | while read ip; do
    nft add element inet filter blacklist { \$ip }
done

echo "Blacklist updated at \$(date)" > /root/security-monitor/blacklist_update.log
EOF

chmod +x /root/security-monitor/monitor.sh
chmod +x /root/security-monitor/update-blacklist.sh

# Thêm crontab
setup_crontab() {
    echo "Setting up crontab jobs..."
    
    # Kiểm tra xem đã có crontab chưa
    crontab -l > /tmp/crontab.tmp 2>/dev/null
    
    # Thêm lệnh cho monitor
    if ! grep -q "security-monitor/monitor.sh" /tmp/crontab.tmp; then
        echo "*/5 * * * * /root/security-monitor/monitor.sh" >> /tmp/crontab.tmp
    fi
    
    # Thêm lệnh cho update blacklist
    if ! grep -q "security-monitor/update-blacklist.sh" /tmp/crontab.tmp; then
        echo "0 */12 * * * /root/security-monitor/update-blacklist.sh" >> /tmp/crontab.tmp
    fi
    
    # Cập nhật crontab
    crontab /tmp/crontab.tmp
    rm /tmp/crontab.tmp
}

# Hàm main
main() {
    # Hiển thị thông tin bắt đầu
    echo "=== Advanced Security Hardening Script ==="
    echo "Starting at $(date)"
    
    # Backup cấu hình hiện tại
    backup_configs
    
    # Kiểm tra môi trường
    check_environment
    
    # Cập nhật hệ thống
    update_system
    
    # Cài đặt các gói cần thiết
    install_packages
    
    # Cấu hình kernel
    configure_kernel
    
    # Cấu hình nftables
    configure_nftables
    
    # Cấu hình suricata
    configure_suricata
    
    # Cấu hình fail2ban
    configure_fail2ban
    
    # Tạo script giám sát
    create_monitor_script
    
    # Cài đặt crontab
    setup_crontab
    
    echo "=== Security hardening completed ==="
    echo "The following components have been configured:"
    echo "- System kernel parameters"
    echo "- nftables firewall"
    echo "- fail2ban"
    echo "- suricata IDS/IPS"
    echo "- Security monitoring scripts"
    echo ""
    echo "Monitoring script will run every 5 minutes"
    echo "Blacklist will be updated every 12 hours"
    echo ""
    echo "Configuration files are backed up in /root/security-backup/"
    echo "Monitor logs are stored in /root/security-monitor/logs/"
    echo ""
    echo "Security hardening completed at $(date)"
}

# Run main function
main