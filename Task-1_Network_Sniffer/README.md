# Task 1: Network Sniffer

## Overview
A real-time Python-based network packet sniffer developed using the `Scapy` library for the CodeAlpha Cybersecurity Internship. The tool captures incoming and outgoing network traffic, parses protocol headers, and displays detailed packet metadata.

## Features
* **Live Traffic Capture:** Captures IP packets in real time across active network interfaces.
* **Protocol Parsing:** Identifies protocols including ICMP, TCP, and UDP.
* **Header Analysis:** Displays Source IP, Destination IP, Protocol type, and Raw Payload content.

## Prerequisites
* Python 3.x
* Scapy Library

Install dependencies:
```bash
pip install scapy
