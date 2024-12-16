# Network Sniffer  

A lightweight and efficient network sniffer that captures and analyzes network packets in real-time. This tool leverages `pcap` to monitor network traffic on a specified interface, allowing you to inspect, filter, and process packets according to your requirements.  

## Features  
- Capture packets on specific network interfaces.  
- Apply customizable filters (e.g., TCP/IP packets, specific ports).  
- Analyze, save, or process packet data with user-defined functions.  

## Prerequisites  
- **Operating System:** Linux, BSD, or any platform supporting `pcap`.  
- **Dependencies:**  
  - `libpcap`
 
    Installation: `wget https://www.tcpdump.org/release/libpcap-1.10.5.tar.xz`
    
    `tar -xzf libpcap-1.10.5.tar.xz`
    
    `cd libpcap-1.10.5 && ./configure`
    
    `make`
    
    `sudo make install`  

## How to Run  

### 1. Clone the Repository  
```bash  
git clone https://github.com/namher-sec/Network-Sniffer.git  
cd Network-Sniffer
```

### 2. Build the Program  
Ensure you have a C compiler (e.g., `gcc`) installed. Then compile the program:  
```bash  
gcc -o sniffer sniffer.c -lpcap  
```

### 3. Run the program
```bash
sudo ./sniffer
```

## IMPORTANT REMINDER:

This tool is not meant to be used in real life production/security environements. Please look into [TCPDump](https://www.tcpdump.org/index.html) or [Wireshark](https://www.wireshark.org/)



