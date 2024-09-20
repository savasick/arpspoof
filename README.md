# ARP Spoof

This Python script performs an one way ARP spoofing attack to intercept traffic. It sends fake ARP messages across the network, associating the attacker's MAC address with the IP address of a legitimate device, such as a router or another computer.

### install

```bash
git clone https://github.com/savasick/arpspoof.git
cd arpspoof
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### run

```bash
sudo python3 arpspoof.py 192.168.5.187
```
