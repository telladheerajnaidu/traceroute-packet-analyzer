# Advanced Traceroute Packet Analyzer

An educational HTML-based simulation that demonstrates traceroute operations at the packet level with detailed protocol analysis and hex dumps.

## 🚀 Features

### Visual Network Simulation
- Interactive network topology with animated packet flow
- Real-time TTL decrementation visualization
- Router-by-router packet traversal animation

### Packet-Level Analysis
- **Complete IPv4 Header Dissection**: All 20 bytes with field-by-field breakdown
- **TTL Field Highlighting**: Visual demonstration of TTL decrementation
- **UDP/ICMP Protocol Support**: Switch between UDP probes and ICMP Echo requests
- **ICMP Time Exceeded Analysis**: Detailed Type 11, Code 0 message structure
- **Hex Dump Display**: Wireshark-style packet examination

### Interactive Features
- Click any packet for detailed inspection
- Step-by-step packet flow control
- Hover tooltips for field explanations
- Protocol switching (UDP vs ICMP traceroute)
- Real-time packet capture simulation

### Educational Components
- Port selection explanation (33434-33523 for UDP)
- TTL behavior across different operating systems
- ICMP error message types and codes
- Protocol field analysis (1=ICMP, 17=UDP)
- Checksum calculation demonstrations

## 🎯 Perfect for
- Network engineers learning traceroute internals
- Students studying TCP/IP protocol stack
- Security professionals analyzing network behavior
- Anyone interested in packet-level networking

## 🖥️ Usage
Open `index.html` in a modern web browser to start the simulation.

### Modes Available:
- **UDP Traceroute**: Traditional traceroute using UDP probes to high ports
- **ICMP Traceroute**: Alternative method using ICMP Echo Request packets
- **Packet Inspector**: Detailed hex dump and field analysis
- **Step Mode**: Manual control for educational pacing

## 🔧 Technical Details
- **Protocols**: IPv4, UDP, ICMP
- **Packet Sizes**: 60 bytes (20-byte IP + 8-byte UDP + 32-byte payload)
- **TTL Range**: 1-30 hops configurable
- **Port Range**: 33434-33523 (UDP traceroute standard)
- **Timeout**: 1-10 seconds configurable

## 📚 Learning Objectives
1. Understand how TTL prevents routing loops
2. Learn ICMP Time Exceeded message structure
3. Analyze UDP vs ICMP traceroute differences
4. Examine packet headers at binary level
5. Comprehend router response mechanisms

## 🌐 Live Demo
[View the packet analyzer](https://yourusername.github.io/traceroute-packet-analyzer) (if hosted on GitHub Pages)

## 🤝 Contributing
Pull requests welcome! This tool is designed to be educational and technically accurate.
