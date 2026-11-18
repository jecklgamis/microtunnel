# Firewall

The relay must allow inbound UDP on port 5040:

```bash
# ufw
sudo ufw allow 5040/udp

# firewalld
sudo firewall-cmd --permanent --add-port=5040/udp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 5040 -j ACCEPT
```

Peers behind NAT do not need any inbound firewall rules — they connect outbound only.
