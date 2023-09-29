#!/bin/bash

# Check if a default network interface is available
default_interface=$(ip route | awk '/default via/ {print $5}')
if [[ -z "$default_interface" ]]; then
  echo "No default network interface found."
  exit 1
fi

# Get the IP address and network from the default network interface
ip_address=$(ip a show dev $default_interface | awk '/inet / {print $2}' | cut -d '/' -f 1)

# Extract the subnet prefix length dynamically
subnet_prefix_length=$(ip a show dev $default_interface | awk '/inet / {print $2}' | cut -d '/' -f 2)

# Construct the network with the extracted subnet prefix length
if [[ "$subnet_prefix_length" -ge 8 && "$subnet_prefix_length" -le 32 ]]; then
  network="$ip_address/$subnet_prefix_length"
else
  echo "Unsupported subnet prefix length: $subnet_prefix_length"
  exit 1
fi

echo "Network: $network"

# Part 1: Network discovery with Nmap
echo "Running network discovery with Nmap..."
nmap -sn $network -oG - | awk '/Up/{print $2}' > live_hosts.txt
echo "Network discovery complete."
echo "Running Ettercap to intercept ARP packets on the network..."
while read -r ip; do
  echo "Running Ettercap for $ip..."
  sudo ettercap -Tq -i eth0 -M arp:remote /$ip// > ettercap_output.log &
done < live_hosts.txt
echo "Ettercap is running in the background."
# Part 2: Port scanning with RustScan and converting to Nmap format
echo "Running port scanning with RustScan..."
while read -r ip; do
  echo "Scanning ports for $ip with RustScan..."
  rustscan -a $ip -r 1-65535 --ulimit 5000 --scripts DEFAULT -- -A -oX "aggressive_scan_$ip.xml"

  # Part 3: Nikto scanning for each live host
  echo "Running Nikto scan for $ip..."
  nikto -h $ip -o "nikto_scan_$ip.txt"
  echo "Nikto scan completed for $ip."
done < live_hosts.txt

# Part 4: Finding ASN for each live host and saving in "asn.txt"
echo "Finding ASN for each live host..."
while read -r ip; do
  echo "Finding ASN for $ip..."
  asn=$(whois $ip | grep -i origin | awk '{print $2}')
  if [[ -n "$asn" ]]; then
    echo "ASN: $asn" >> asn.txt
  else
    echo "ASN not found for $ip." >> asn.txt
  fi
done < live_hosts.txt

# Part 5: Perform traceroute for each live host and save in "traceroute.txt"
echo "Performing traceroute for each live host..."
while read -r ip; do
  echo "Performing traceroute for $ip..."
  traceroute -m 30 $ip >> traceroute.txt
done < live_hosts.txt

echo "Aggressive scanning, Nikto scanning, ASN lookup, and traceroute complete."
