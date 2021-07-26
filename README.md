# Http-packet-stealer
A program that listens to TCP packets then steals the data if it’s an HTTP request and displays that request, using type of sockets, which is SOCK_RAW, this type of sockets access to everything as the operating system, depending on its address family. 
# What does the program exactly do?
1. IP packets are parsed to extract their data. 
2. After that if they hold a TCP packet, we'll check if that data can be decoded as utf-8 characters or not. 
3. If so, we'll consider this as an HTTP packet.
4. Then it gets printed directly to the console.
# Implementation steps:
1. code can parse a byte literal containing an IP .
2. code has sockets set up and can capture TCP packets ONLY .
3. code extracts the IHL field correctly from the IP header.
4. code extracts source and destination IPs from the IP header and extracts the payload .
5. code extracts TCP source and destination ports.
6. code extracts TCP data offset .
7. code extracts TCP payload and prints it.


