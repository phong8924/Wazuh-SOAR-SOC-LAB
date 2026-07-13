# Wazuh-SOAR-SOC-Lab
# Wazuh SOAR SOC Lab

A hands-on Security Operations Center lab for endpoint monitoring, detection engineering, alert correlation, threat intelligence enrichment, and incident management.

## Objectives

- Collect Windows telemetry using Sysmon and Wazuh Agent
- Develop custom Wazuh detection rules
- Correlate related security events
- Reduce false positives and visualize security events
- Automate alert processing with Shuffle
- Manage incidents using TheHive
- Enrich observables using Cortex and VirusTotal

## Lab Architecture

| System | Role | IP address |
|---|---|---|
| Ubuntu Server 24.04 | Wazuh, Shuffle, TheHive and Cortex | 192.168.56.10 |
| Kali Linux | Attacker and analyst workstation | 192.168.56.20 |
| Windows 10 | Victim endpoint with Wazuh Agent and Sysmon | 192.168.56.30 |

The virtual machines communicate through a VirtualBox Host-Only network.

## Implementation Progress

- [ ] Phase 1: Infrastructure and telemetry collection
- [ ] Phase 2: Custom detection rules
- [ ] Phase 3: Alert correlation
- [ ] Phase 4: False-positive reduction
- [ ] Phase 5: Dashboards and reporting
- [ ] Phase 6: SOAR automation

## Repository Structure

- `assets/`: Architecture diagrams and screenshots
- `automation/`: Lab management and testing scripts
- `config/wazuh/`: Wazuh rules and configuration
- `config/shuffle/`: Shuffle workflow resources
- `docs/`: Implementation documentation

## References

This project is implemented independently in a personal lab environment. The following repository is used as a technical reference:

- https://github.com/Rameez-03/SOC-Lab
