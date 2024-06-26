# DNS Poisoning Attacks

## Introduction

DNS (Domain Name System) poisoning is a type of cyber attack where the attacker introduces malicious DNS records into the DNS resolver cache. This can lead to redirecting legitimate traffic to malicious websites, intercepting sensitive information, and other security risks.

This repository contains two Python scripts that demonstrate DNS poisoning attacks using the Scapy library.

## Naive DNS Attack

The naive DNS attack script (`naive_dns_attack.py`) is a simple implementation of DNS poisoning. It intercepts DNS query packets and responds with spoofed DNS response packets containing a malicious IP address.

## Dynamic DNS Attack

The dynamic DNS attack script (`dynamic_dns_attack.py`) is an advanced implementation of DNS poisoning. It dynamically generates spoofed DNS response packets with sequential IDs based on the captured DNS query packets.

These scripts are for educational purposes only. Unauthorized use of these scripts for malicious purposes is illegal and unethical. Use them responsibly and only on networks you own or have permission to test.
