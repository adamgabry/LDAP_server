### showing the specific packet with id `frame.number`  
- tshark -r file.pcap -Y "frame.number == 8" -x

### writing the capture to `*.pcap`  
- tshark -i any -f "port 389" -w file.pcap

### showing all packets captured of `tshark.pcap`
- tshark -r tshark.pcap