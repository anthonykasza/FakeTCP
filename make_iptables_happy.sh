sudo iptables -F
sudo iptables -X
sudo iptables -A OUTPUT -s 127.0.0.10 -j ACCEPT
sudo iptables -A OUTPUT -s 127.0.0.20 -j ACCEPT
sudo iptables -A INPUT -s 127.0.0.10 -j ACCEPT
sudo iptables -A INPUT -s 127.0.0.20 -j ACCEPT
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP

