#!/bin/bash
set -e
# CLI arguments
LOCAL=''
LOCAL_INSTALL=''
NETWORK_TYPE=''

while [[ $# -gt 0 ]]; do
    case "$1" in
        -l|--local)
        LOCAL="$2"
        LOCAL_INSTALL="1"
        shift
        ;;
        *)
                # unknown option
        ;;
    esac
    shift # past argument or value
done



if grep -q "#net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g" "/etc/sysctl.conf"
    sysctl -p
fi

if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf && sysctl -p
fi

#wget https://install.direct/go.sh && chmod +x ./go.sh && ./go.sh && rm ./go.sh
if [ ! -x /usr/bin/curl ]; then
	apt-get update && apt-get install curl -y
fi
if [ ! -x /usr/bin/v2ray ]; then
	if [[ $LOCAL_INSTALL -eq 1 ]]; then
		chmod +x ./go.sh && ./go.sh --local $LOCAL
		rm ./go.sh
	else
		bash <(curl -L -s https://install.direct/go.sh)
	fi
fi

read -r -p "选择网络类型?
 1.ws 
 2.ws+tls
 选择：" NETWORK_TYPE


if [[ $NETWORK_TYPE -eq 1 ]]; then
	cp ./config/ws-config.json /etc/v2ray/config.json
	read -r -p "请输入地址(ADDRESS): " ADDRESS
	read -r -p "请输入端口(PORT): " PORT
	read -r -p "请输入用户ID(USER_ID): " USER_ID
	read -r -p "请输入额外ID(ALTERID): " ALTERID
	read -r -p "请输入伪装域名(HOST): " HOST
	read -r -p "请输入伪装路径(PATH): " HOST_PATH

	sed -i "s/==ADDRESS/$ADDRESS/g" "/etc/v2ray/config.json"
	sed -i "s/==PORT/$PORT/g" "/etc/v2ray/config.json"
	sed -i "s/==USER_ID/$USER_ID/g" "/etc/v2ray/config.json"
	sed -i "s/==ALTERID/$ALTERID/g" "/etc/v2ray/config.json"
	sed -i "s#==HOST#$HOST#g" "/etc/v2ray/config.json"
	sed -i "s#==PATH#$HOST_PATH#g" "/etc/v2ray/config.json"

fi

if [[ $NETWORK_TYPE -eq 2 ]]; then
	cp ./config/ws-tls-config.json /etc/v2ray/config.json
	read -r -p "请输入地址(ADDRESS): " ADDRESS
	read -r -p "请输入端口(PORT): " PORT
	read -r -p "请输入用户ID(USER_ID): " USER_ID
	read -r -p "请输入额外ID(ALTERID): " ALTERID
	read -r -p "请输入伪装域名(HOST): " HOST
	read -r -p "请输入伪装路径(PATH): " HOST_PATH

	sed -i "s/==ADDRESS/$ADDRESS/g" "/etc/v2ray/config.json"
	sed -i "s/==PORT/$PORT/g" "/etc/v2ray/config.json"
	sed -i "s/==USER_ID/$USER_ID/g" "/etc/v2ray/config.json"
	sed -i "s/==ALTERID/$ALTERID/g" "/etc/v2ray/config.json"
	sed -i "s#==HOST#$HOST#g" "/etc/v2ray/config.json"
	sed -i "s#==PATH#$HOST_PATH#g" "/etc/v2ray/config.json"

fi


ip rule add fwmark 1 table 100 
ip route add local 0.0.0.0/0 dev lo table 100

# 代理局域网设备
iptables -t mangle -N V2RAY
iptables -t mangle -A V2RAY -d 127.0.0.1/32 -j RETURN
iptables -t mangle -A V2RAY -d 224.0.0.0/4 -j RETURN 
iptables -t mangle -A V2RAY -d 255.255.255.255/32 -j RETURN 
iptables -t mangle -A V2RAY -d 192.168.0.0/16 -p tcp -j RETURN # 直连局域网，避免 V2Ray 无法启动时无法连网关的 SSH，如果你配置的是其他网段（如 10.x.x.x 等），则修改成自己的
iptables -t mangle -A V2RAY -d 192.168.0.0/16 -p udp ! --dport 53 -j RETURN # 直连局域网，53 端口除外（因为要使用 V2Ray 的 
iptables -t mangle -A V2RAY -d 172.18.0.0/16 -p tcp -j RETURN
iptables -t mangle -A V2RAY -d 172.18.0.0/16 -p udp ! --dport 53 -j RETURN
iptables -t mangle -A V2RAY -p udp -j TPROXY --on-port 12345 --tproxy-mark 1 # 给 UDP 打标记 1，转发至 12345 端口
iptables -t mangle -A V2RAY -p tcp -j TPROXY --on-port 12345 --tproxy-mark 1 # 给 TCP 打标记 1，转发至 12345 端口
iptables -t mangle -A PREROUTING -j V2RAY # 应用规则

mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4

TPROXY_SERVICE_FILE=/etc/systemd/system/tproxyrule.service

if [ ! -f "$TPROXY_SERVICE_FILE" ]; then
    cat > $TPROXY_SERVICE_FILE <<EOF
[Unit]
Description=Tproxy rule
After=network.target
Wants=network.target
[Service]
Type=oneshot
#注意分号前后要有空格
ExecStart=/sbin/ip rule add fwmark 1 table 100 ; /sbin/ip route add local 0.0.0.0/0 dev lo table 100 ; /sbin/iptables-restore /etc/iptables/rules.v4
[Install]
WantedBy=multi-user.target
EOF
systemctl enable tproxyrule
fi

sed -ie '/^RestartPreventExitStatus/a LimitNPROC=500\nLimitNOFILE=1000000' /etc/systemd/system/v2ray.service

systemctl daemon-reload && systemctl restart v2ray

#测试连接
#curl -so /dev/null -w "%{http_code}" google.com -x socks5://127.0.0.1:1080
