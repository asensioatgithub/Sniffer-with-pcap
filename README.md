# Sniffer-with-pcap
## For the latest version of labcap, please see: 
        http://www.tcpdump.org/#latest-releases
## For the detailed usage of lapcap, please see:
        http://www.tcpdump.org/pcap.html
## Install lapcap:
　       　./configure
　  　     make
　　       make install
 ## gcc -o sniffer sniffer.c -lpcap -lm
 ## sudo ./sniffer -i wlp3s0 -t tcp -p 23 -x -m
       -i interface
       -t protocol type
       -s source address
       -d destination address
       -p port number
       -m printf mac-address
       -x printf hex data
