# dnsfilterd
Simple DNS server daemon with blacklist.
This is sample project.

What works:
- redirection of DNS queries to openDNS server
- requests are UDP
- blacklist with domains and hosts filtering
- running as daemon

What not:
- no cache
- no packet loss control
- UDP packets only

#Usage:
Run:
./dnsfilterd 5300 /<dir>/blacklist

Chech if running:
ps -u <user> | grep dnsfilterd

Make request:
nslookup google.com 127.0.0.1 -port=5300

Kill:
cat /tmp/dnsfilterd.lock | xargs kill -s SIGTERM
