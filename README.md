# Advanced DoS Testing Tool

**⚠️ IMPORTANT: FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**

A sophisticated Python-based Denial-of-Service testing tool designed for authorized penetration testing, security research, and educational demonstrations.

## 🚨 Legal Disclaimer

This tool is developed **STRICTLY** for:
- Authorized penetration testing
- Security research and education
- Academic purposes
- Testing your own systems

**NEVER use this tool against systems you do not own or without explicit written permission.** Unauthorized use may violate local and international laws. The developers are not responsible for any misuse.

## 🔥 Important Note on Rate Limiting

**⚠️ SERVICES WITH RATE LIMITING ARE DIFFICULT TO DoS**
Modern web services and APIs implement sophisticated rate limiting, DDoS protection, and load balancing that make traditional DoS attacks largely ineffective against properly configured systems. This tool primarily demonstrates basic attack vectors for educational purposes.

## 🌐 Platform Compatibility

This tool was primarily designed and tested on **Windows** platforms, however it does not mean that it won't work on Linux systems. The tool uses cross-platform Python libraries and should function on most operating systems with Python support, though some features may behave differently across platforms.

## Features

### 🎯 Attack Vectors
- **Regular Flood Attack** - Mixed TCP/UDP flooding
- **UDP Flood** - Connectionless high-speed attacks
- **TCP Flood** - Connection-based flooding
- **Advanced Port Scanning** with service detection
- Multiple configuration presets

### 🔍 Reconnaissance
- Advanced port scanning with service detection
- Common ports, top ports, and full range scanning
- Authentication service detection
- Banner grabbing
- Service identification

### ⚙️ Configuration
- Adjustable thread counts (1-10,000)
- Custom packet sizes
- Configurable attack duration
- Multiple preset configurations:
  - Standard (150 threads)
  - Strong (500 threads) 
  - Ultra (1000 threads)

## Donations
Support ongoing development with donations:  

💰 **Ethereum wallet:** `0x4520bEd2BC14389646B9c22b7A2D5d095C168d12` 💰


## 📋 Prerequisites

```bash
# Required Python packages
pip install colorama
