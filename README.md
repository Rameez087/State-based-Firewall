# Python-Based Firewall Application

## Overview
This is a Python-based stateful firewall application that allows users to define rules, monitor real-time network traffic, and analyze logs of allowed and blocked packets. It also implements state-based connection tracking for robust decision-making.

## Features
- **User-Defined Rules**: Configure IP, port, and protocol-specific rules.
- **Real-Time Monitoring**: Track network traffic live.
- **Logging**: Separate logs for allowed, blocked, and invalid packets.
- **Connection Tracking**: Manage the state of TCP connections using a connection table.

## Requirements
- Python 3.8 or above
- Dependencies:
  - PyQt5
  - Scapy
