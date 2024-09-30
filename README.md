# ARP Spoof

This Python script performs ARP spoofing attack to intercept traffic. It sends fake ARP messages across the network, associating the attacker's MAC address with the IP address of a legitimate device, such as a router or another computer.

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

another script with out Ethernet layer
```bash
sudo python3 arpspoofing 192.168.5.187
```

#### to check if ARP spoofing works

```bash
sudo python3 sniffer.py 192.168.5.187
```

use [scanner](https://github.com/savasick/simpscanner) to get ip
