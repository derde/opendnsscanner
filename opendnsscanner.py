#! /usr/bin/python3

"""
Scan a list of IP addresses for open DNS servers

# Like this, but fast:
nmap -sU -p 53 -sV -P0 –script dns-recursion 8.8.8.8
  -sU = UDP scan
  -p 53 = only scan for port 53 (the “dns”-port)
  -sV = Probe open ports to determine service/version info
  -P0 = Treat all hosts as online
"""

import socket
import struct
import time
import dns, dns.message, dns.exception, dns.rdatatype
import sys
import ipaddress
import optparse

# Function to create a DNS query for A record of isc.org
def create_dns_query(domain):
    # Use dnspython to create a DNS query for A record of the domain
    query = dns.message.make_query(domain, dns.rdatatype.A)
    return query.to_wire()

# Function to parse the DNS reply using dnspython
def parse_dns_reply(reply):
    try:
        # Parse the DNS reply using dnspython
        message = dns.message.from_wire(reply)

        # Check if the reply contains A records
        if message.answer:
            for answer in message.answer:
                if answer.rdtype == dns.rdatatype.A:  # Ensure it's an A record
                    ip = list(answer.items.items())[0][0] # 1st answer, key value
                    return ip
    except (dns.exception.DNSException, Exception) as e:
        sys.stderr.write(f"Error parsing DNS reply: {e}\n")
    return None

# Function to send a DNS query and listen for replies
def send_dns_query(target_ip,open):
    global sock
    global query

    # Send the DNS query for "isc.org"
    if target_ip:
        sock.sendto(query, (target_ip, 53))  # DNS uses port 53

    while True:
        try:
            # Wait for a response within the timeout period
            reply, addr = sock.recvfrom(512)  # Maximum DNS packet size
            ip = parse_dns_reply(reply)
            if ip:
                # print(addr[0]) # print(f"Received valid DNS reply from {addr[0]}: {ip}")
                open[addr[0]]=True # print(f"Received valid DNS reply from {addr[0]}: {ip}")
            else:
                sys.stderr.write(f"invalid-reply:{addr[0]}\n")
        except socket.timeout:
            # extra sending delay for lots of replies 
            break
    return open

if __name__ == '__main__':
    defaultheaders=['Content-Type: application/json']
    usage="Usage: %prog [options] subnet ...\n"
    parser=optparse.OptionParser(usage)
    parser.add_option("--domain",  '-d', dest="domain", action="store", default='isc.org', help="When the domain is this...")
    parser.add_option("--mbps",    '-s', dest="mbps", type="float", default=1, help="Guesstimated transmission speed in mbps")
    parser.add_option("--url",     '-u', dest="report_url", action="store", default='', help="Where to POST a JSON report to")
    parser.add_option("--header",  '-H', dest="headers", action="append", default=defaultheaders, help="headers for json POST")
    parser.add_option("--verbose", '-v', dest="verbose", action="count", default=0, help="up the verbosityness level by one")
    (options,args) = parser.parse_args()
    domain = options.domain
    bps=options.mbps*1000000

    query = create_dns_query(domain)
    timeout=8*(len(query)+46)/bps # doesn't include reply waiting .. 46 is for ethernet+ip+udp header bytes
    if options.verbose>1:
        sys.stderr.write(f'# timeout={timeout:0.4f}')
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)  # Set the timeout to 1ms

    # Bind to any local address and some port
    sock.bind(('', 12355))

    openresolvers={}
    for s in args:
        subnet=ipaddress.ip_network(s,strict=False)
        for host in subnet.hosts():
            send_dns_query(str(host),openresolvers)

    sock.settimeout(2) # last chance for responses
    send_dns_query(None,openresolvers)

    # Close the socket
    sock.close()

reports=[]
for resolver in openresolvers.keys():
    print(resolver)
    report={
        'topic': 'sec.dns-open',
        'username': resolver,
        'hostname': socket.gethostname().split('.')[0],
        'value': f'Open resolver {resolver}. Client must secure or firewall',
    }
    reports.append(report)

if options.report_url:
    import json
    import requests
    url=options.report_url
    userheaders={}
    for h in options.headers:
        k,v=h.split(':',1)
        userheaders[k.strip()]=v.strip()
    response = requests.post(url, json=reports, headers=userheaders, timeout=120)

