# ARP Poisoning Attack Detector

This is a simple ARP poisoning attack detector tool named arpwatch.py. It monitors ARP traffic on a specified or default network interface and prints a warning message whenever an existing MAC-IP binding changes.
Features

Reads the current ARP cache entries at startup and uses them as the ground truth.
Passively monitors ARP traffic.
Prints a warning message whenever an existing MAC-IP binding changes.

# Specifications
```
arpwatch.py [-i interface]
```

-i Live capture from the network device <interface> (e.g., eth0).
If not specified, the program automatically selects a default interface to listen on.
Capture continues indefinitely until the user terminates the program.

# Usage

Run the script with python arpwatch.py -i [interface] to monitor ARP traffic on the specified network interface.
If no interface is specified, the script will automatically select a default interface.
The script must be run with root privileges to capture packets.

# Installation

Ensure Python 3 is installed on your system.
Install the required packages, Scapy and netifaces, using

```
pip install -r requirements.txt
```
Run the script using python arpwatch.py.

# Example

Suppose the current ARP cache is:
```
10.0.0.1 00:11:22:33:44:55
10.0.0.2 00:11:22:33:44:66
```
And an ARP packet is captured:

```
ARP is at 24:a4:3c:b3:15:23 says 10.0.0.1
```

The script will print:
```
WARNING: 10.0.0.1 changed from 00:11:22:33:44:55 to 24:a4:3c:b3:15:23
```
# Compatibility

This tool is compatible with Unix-like operating systems.
Ensure to run the script with root privileges for packet capturing.

# License

This tool is licensed under the MIT License. Please see the LICENSE file for details.