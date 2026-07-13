# Phase 1 — Thiết lập Infrastructure

## Tổng quan

Xây dựng lab cơ bản: ba VM trên Host-Only network, Wazuh all-in-one trên Ubuntu, agent + Sysmon trên Windows 10, và xác minh end-to-end.

---

## 1. VirtualBox Network

Tạo Host-Only adapter (chạy trên Windows host bằng PowerShell với quyền Administrator):

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif create
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter #2" --ip 192.168.56.1 --netmask 255.255.255.0
```

Gán `VirtualBox Host-Only Ethernet Adapter #2` làm network adapter thứ hai trên cả ba VM.

---

## 2. Thiết lập Ubuntu VM

**Specs:** 8GB RAM, 100GB disk, 10 vCPUs  
**Adapters:** Adapter 1 = Host-Only (`192.168.56.10`), Adapter 2 = Bridged (internet để cài đặt)

### Static IP (Netplan)

```yaml
# /etc/netplan/50-cloud-init.yaml
network:
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [192.168.56.10/24]
    enp0s8:
      dhcp4: true
  version: 2
```

Vô hiệu hóa cloud-init network management để cấu hình được duy trì:

```bash
sudo bash -c 'echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg'
sudo netplan apply
```

### Cài đặt Wazuh

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Quá trình này mất 10–20 phút. Credentials được hiển thị khi hoàn tất — hãy lưu lại.

### Khắc phục startup timeout của wazuh-manager

```bash
sudo systemctl edit wazuh-manager
```

Thêm:

```ini
[Unit]
After=wazuh-indexer.service

[Service]
TimeoutStartSec=300
Restart=on-failure
RestartSec=15
```

```bash
sudo systemctl daemon-reload
```

---

## 3. Thiết lập Kali Linux

**Adapter 2:** Host-Only → `192.168.56.20`

```bash
sudo nmcli con add type ethernet ifname eth1 con-name host-only ip4 192.168.56.20/24
sudo nmcli con modify host-only connection.autoconnect yes
sudo nmcli con up host-only
```

Truy cập Wazuh dashboard từ Kali: `https://192.168.56.10`

---

## 4. Thiết lập Windows 10 Agent

**Adapter 2:** Host-Only → `192.168.56.30` (thiết lập thủ công trong IPv4 settings, không có gateway)

### Cài đặt Wazuh Agent

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi" -OutFile "C:\wazuh-agent.msi"
msiexec /i C:\wazuh-agent.msi WAZUH_MANAGER="192.168.56.10" /q
NET START WazuhSvc
```

### Cài đặt Sysmon

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

### Cấu hình Log Collection

Thêm vào `C:\Program Files (x86)\ossec-agent\ossec.conf`, bên trong `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Các channel Security, System và Application được bao gồm theo mặc định.

```powershell
NET STOP WazuhSvc
NET START WazuhSvc
```

---

## 5. Xác minh

- Agent hiển thị **Active** trong dashboard: Menu → Agents
- Events đang được truyền: nhấp vào agent → tab Events
- Các MITRE ATT&CK tactics được điền từ baseline Windows activity
