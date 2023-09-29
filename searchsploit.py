import os
import re
import subprocess
import xml.etree.ElementTree as ET

# Service name mapping dictionary
service_mapping = {
    "http": "Apache httpd",
    "nginx": "nginx",
    "ssh": "OpenSSH",
    "ftp": "vsftpd",
    "telnet": "telnet",
    "smtp": "Postfix",
    "imap": "Dovecot",
    "pop3": "Dovecot",
    "dns": "BIND",
    "dhcp": "ISC DHCP",
    "snmp": "SNMP",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "oracle": "Oracle Database",
    "smb": "Samba",
    "ldap": "OpenLDAP",
    "rsync": "rsync",
    "mongodb": "MongoDB",
    "vnc": "VNC",
    "rdp": "RDP",
    "ntp": "NTP",
    "memcached": "Memcached",
    "redis": "Redis",
    "memcache": "Memcached",
    "rmi": "RMI Registry",
    "nfs": "NFS",
    "rpc": "RPC",
    "ike": "IKE",
    "tftp": "TFTP",
    "rpcbind": "RPCbind",
    "mssql": "Microsoft SQL Server",
    "oracle-tns": "Oracle TNS Listener",
    "cassandra": "Apache Cassandra",
    "mqtt": "MQTT",
    "coap": "CoAP",
    "modbus": "Modbus",
    "dnp3": "DNP3",
    "enip": "EtherNet/IP",
    "bacnet": "BACnet",
    "iec-60870-5-104": "IEC 60870-5-104",
    "iec-61850": "IEC 61850",
    "s7": "Siemens S7",
    "iis": "Microsoft IIS",
    "winrm": "Windows Remote Management",
    "netbios": "NetBIOS",
    "upnp": "UPnP",
    "mssql-udp": "Microsoft SQL Server (UDP)",
    "sccm": "Microsoft SCCM",
    "ike-version": "IKE Version",
    "bgp": "BGP",
    "rip": "RIP",
    "ospf": "OSPF",
    "isis": "ISIS",
    "ldp": "LDP",
    "biff": "Biff",
    "printer": "Printer",
    "vrrp": "VRRP",
    "sip": "SIP",
    "radmin": "Radmin",
    "nntp": "NNTP",
    "kerberos": "Kerberos",
    "radius": "RADIUS",
    "radacct": "RADIUS Accounting",
    "ldap-admin": "LDAP Admin",
    "ldap-admins": "LDAP Admins",
    "sftp": "SFTP",
    "imap3": "IMAP3",
    "pcanywhere": "PCAnywhere",
    "webmin": "Webmin",
    "distcc": "distcc",
    "imap4": "IMAP4",
    "ms-wbt-server": "Microsoft WBT Server",
    "rdp-udp": "RDP (UDP)",
    "radmin-udp": "Radmin (UDP)",
    "openvpn": "OpenVPN",
    "pptp": "PPTP",
    "samsung-printer": "Samsung Printer",
    "snmp-trap": "SNMP Trap",
    "socks": "SOCKS",
    "ssl": "SSL",
    "telnetd": "telnetd",
    "tftp-data": "TFTP Data",
    "vmware-auth": "VMware Authentication",
    "vmware-vmci": "VMware VMCI",
    "xmpp": "XMPP",
    "kerberos-sec": "Kerberos SEC",
    "isakmp": "ISAKMP",
    "bacnet-awt": "BACnet AWT",
    "bacnet-ms-tsm": "BACnet MS/TP",
    "bacnet-mstp": "BACnet MSTP",
    "bacnet-ptp": "BACnet PTP",
    "bacnet-udp": "BACnet (UDP)",
    "bacnet": "BACnet/IP",
    "bacnet-ip": "BACnet/IP",
    "bacnet-eth": "BACnet Ethernet",
    "bacnet-ms-tp": "BACnet MS/TP",
    "bacnet-mstp": "BACnet MSTP",
    "bacnet-ptp": "BACnet PTP",
    "bacnet-udp": "BACnet (UDP)",
    "bacnet-vlan": "BACnet VLAN",
    "directprint": "Direct Print",
    "printer-queue": "Printer Queue",
    "printer-status": "Printer Status",
    "printer-uri": "Printer URI",
    "printer-uuid": "Printer UUID",
    "raw-printer": "Raw Printer",
    "raw-printer-port": "Raw Printer Port",
    "raw-printer-job": "Raw Printer Job",
    "raw-printer-jobs": "Raw Printer Jobs",
    "biff": "Biff",
    "uucp": "UUCP",
    "uucp-rlogin": "UUCP rlogin",
    "uucp-login": "UUCP login",
    "printer-queue": "Printer Queue",
    "printer-status": "Printer Status",
    "printer-uri": "Printer URI",
    "printer-uuid": "Printer UUID",
    "raw-printer": "Raw Printer",
    "raw-printer-port": "Raw Printer Port",
    "raw-printer-job": "Raw Printer Job",
    "raw-printer-jobs": "Raw Printer Jobs",
    "fax": "Fax",
    "fax2mail": "Fax to Mail",
    "fax2email": "Fax to Email",
    "email2fax": "Email to Fax",
    "email2fax-gw": "Email to Fax Gateway",
    "fax2email-gw": "Fax to Email Gateway",
    "imap2": "IMAP2",
    "imap3": "IMAP3",
    "imap4": "IMAP4",
    "sqlnet": "SQLNet",
    "oracle-sqlnet": "Oracle SQLNet",
    "oracle-sqlplus": "Oracle SQL*Plus",
    "oracle-listener": "Oracle Listener",
    "oracle-https": "Oracle HTTPS",
    "oracle-dbsnmp": "Oracle DBSNMP",
    "oracle-em": "Oracle EM",
    "oracle-tns": "Oracle TNS Listener",
    "oracle-tns-version": "Oracle TNS Listener Version",
    "oracle-rep-utility": "Oracle Replication Utility",
    "oracle-rep-server": "Oracle Replication Server",
    "oracle-rep-agent": "Oracle Replication Agent",
    "oracle-rep-cmd": "Oracle Replication Command",
    "oracle-sid": "Oracle SID",
    "oracle-database": "Oracle Database",
    "oracle-db": "Oracle Database",
    "oracle-tns-listener": "Oracle TNS Listener",
    "oracle-web-https": "Oracle Web HTTPS",
    "oracle-oid": "Oracle OID",
    "oracle-oms": "Oracle OMS",
    "oracle-em": "Oracle EM",
    "oracle-tns": "Oracle TNS Listener",
    "oracle-tns-version": "Oracle TNS Listener Version",
    "oracle-listener": "Oracle Listener",
    "oracle-version": "Oracle Version",
    "oracle-https": "Oracle HTTPS",
    "oracle-https-admin": "Oracle HTTPS Admin",
    "oracle-dbsnmp": "Oracle DBSNMP",
    "oracle-em": "Oracle EM",
    "oracle-dbconsole": "Oracle DBConsole",
    "oracle-xe": "Oracle XE",
    "oracle-xe-https": "Oracle XE HTTPS",
    "oracle-database": "Oracle Database",
    "oracle-db": "Oracle Database",
    "oracle-tns-listener": "Oracle TNS Listener",
    "oracle-web-https": "Oracle Web HTTPS",
    "oracle-oid": "Oracle OID",
    "oracle-oms": "Oracle OMS",
    "oracle-em": "Oracle EM",
    "oracle-tns": "Oracle TNS Listener",
    "oracle-tns-version": "Oracle TNS Listener Version",
    "oracle-listener": "Oracle Listener",
    "oracle-version": "Oracle Version",
    "oracle-https": "Oracle HTTPS",
    "oracle-https-admin": "Oracle HTTPS Admin",
    "oracle-dbsnmp": "Oracle DBSNMP",
    "oracle-em": "Oracle EM",
    "oracle-dbconsole": "Oracle DBConsole",
    "oracle-xe": "Oracle XE",
    "oracle-xe-https": "Oracle XE HTTPS",
    "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL",
    "openvpn": "OpenVPN",
    "poptop": "PoPToP",
    "p2p": "P2P",
    "sandbox": "Sandbox",
    "socks": "SOCKS",
    "dlep": "DLEP",
    "dlep-control": "DLEP Control",
    "sshell": "SSHell",
    "sshell-server": "SSHell Server",
    "sshell-client": "SSHell Client",
    "ssl": "SSL",
    "ssl-pm": "SSL-PM",
    "telnetd": "telnetd",
    "tftp": "TFTP",
    "tftp-data": "TFTP Data",
    "tftp-audit": "TFTP Audit",
    "tftp-event": "TFTP Event",
    "vmware-auth": "VMware Authentication",
    "vmware-authd": "VMware Authd",
    "vmware-authd-log": "VMware Authd Log",
    "vmware-authd-ml": "VMware Authd ML",
    "vmware-authd-rb": "VMware Authd RB",
    "vmware-authd-sf": "VMware Authd SF",
    "vmware-authd-si": "VMware Authd SI",
    "vmware-authd-sm": "VMware Authd SM",
    "vmware-authd-ss": "VMware Authd SS",
    "vmware-authd-sv": "VMware Authd SV",
    "vmware-authd-sv": "VMware Authd SV",
    "vmware-authd-sv": "VMware Authd SV",
    "vmware-authd-tb": "VMware Authd TB",
    "vmware-authd-tl": "VMware Authd TL",
    "vmware-authd-tt": "VMware Authd TT"
}

def extract_service_info(scan_output):
    services = {}
    root = ET.fromstring(scan_output)
    for host in root.findall('host'):
        for port in host.findall('ports/port'):
            port_id = port.get('portid')
            service_elem = port.find('service')
            if service_elem is not None:
                service = service_elem.get('name')
                version = service_elem.get('version')

                # Map the service name if there is a known mapping
                if service in service_mapping:
                    service = service_mapping[service]

                services[int(port_id)] = {"service": service, "version": version}
            else:
                print(f"No service information found for port {port_id}. Skipping.")
    return services

def search_exploits(services, vuln_file):
    for port, info in services.items():
        service = info["service"]
        version = info["version"]
        if version:
            print(f"Searching exploits for {service} version: {version}")
            try:
                search_result = subprocess.check_output(['searchsploit', f"{service} {version}"])
                vuln_file.write(f"\n\n{'='*30}\n\n")
                vuln_file.write(f"Search results for {service} version: {version}\n\n")
                vuln_file.write(search_result.decode('utf-8'))
            except subprocess.CalledProcessError as e:
                print(f"Error occurred while searching exploits for {service} version {version}. Error: {e}")
        else:
            print(f"No version information found for {service} on port {port}. Skipping search.")

# Get a list of all XML files in the directory
xml_files = [file for file in os.listdir() if file.endswith('.xml')]

# Loop through each XML file
for xml_file in xml_files:
    with open(xml_file, "r") as f:
        xml_data = f.read()

    # Extract service information from the XML data
    service_info = extract_service_info(xml_data)

    # Write exploit search results to a file named "vuln_<ip_address>.txt"
    ip_address = re.search(r'aggressive_scan_(\d+\.\d+\.\d+\.\d+)\.xml', xml_file).group(1)
    output_file = f"vuln_{ip_address}.txt"
    with open(output_file, "w") as vuln_file:
        search_exploits(service_info, vuln_file)
