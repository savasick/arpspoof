# ARP Spoof

This Python script performs an ARP spoofing attack to disable devices and intercept traffic. It sends forged ARP messages across the network, associating the attacker's MAC address with the IP address of a legitimate device, such as a router or another computer.

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
