# Phase 2 — Normalisation

## Tổng quan

Normalisation là quá trình chuyển đổi các khối raw log thành những field có cấu trúc và có thể truy vấn — sau đó viết các rule để phát hiện hành vi đáng ngờ dựa trên những field đó.

Hai component đảm nhiệm việc này trong Wazuh:

- **Decoders** — phân tích raw log và trích xuất các field được đặt tên
- **Rules** — kiểm tra các field đó và kích hoạt alert khi có kết quả khớp

Wazuh đi kèm các decoder và rule tích hợp sẵn để xử lý Sysmon, Windows Event Logs và hàng trăm nguồn khác. Phase 2 phát triển dựa trên các thành phần đó bằng các custom rule được thiết kế riêng cho những attack scenario trong lab này.

---

## Pipeline hoàn chỉnh

```
Windows 10 chạy whoami.exe
        │
        ▼
Sysmon ghi nhận Event ID 1 (Process Creation)
        │
        ▼
Wazuh Agent gửi raw JSON log đến manager (port 1514)
        │
        ▼
Decoder đọc raw log → trích xuất các structured field:
    win.eventdata.image       = C:\Windows\System32\whoami.exe
    win.eventdata.commandLine = whoami
    win.system.eventID        = 1
    win.system.channel        = Microsoft-Windows-Sysmon/Operational
        │
        ▼
Rules engine kiểm tra các decoded field với tất cả rule đã được load
        │
        ├── Built-in rule 92031 khớp → "Discovery activity executed"
        └── Rule 100300 của chúng ta khớp → "Discovery: Recon command executed"
        │
        ▼
Alert được lưu trong indexer → hiển thị trong dashboard
```

---

## Cấu trúc của Rule

```xml
<rule id="100300" level="6">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)(whoami|net|net1)\.exe</field>
    <description>Discovery: Recon command executed - $(win.eventdata.image)</description>
    <mitre>
        <id>T1082</id>
    </mitre>
</rule>
```

| Component | Mục đích |
|---|---|
| `id` | Số rule duy nhất. Custom rule phải bắt đầu từ **100000+** |
| `level` | Severity từ 1–15. 1–6 info, 7–10 suspicious, 11–14 likely malicious, 15 critical |
| `if_group` | Pre-filter — chỉ kiểm tra rule này với các log đã thuộc group này. Do decoder gán |
| `field` | Detection condition — decoded field phải khớp với regex |
| `type="pcre2"` | Sử dụng PCRE2 regex. `(?i)` giúp so khớp không phân biệt chữ hoa, chữ thường |
| `description` | Nội dung alert hiển thị trong dashboard. `$(field.name)` chèn giá trị thực tế |
| `mitre` | Gắn MITRE ATT&CK technique ID cho alert |

Nhiều điều kiện `<field>` trong một rule = **AND logic** (tất cả đều phải khớp).

---

## Rule ID Namespace

```
100001 - 100099  →  Execution
100100 - 100199  →  Persistence
100200 - 100299  →  Credential Access
100300 - 100399  →  Discovery
100400 - 100499  →  Defense Evasion
100500 - 100599  →  C2 / Network
```

---

## Tên Sysmon Group

Wazuh gán một group cho mỗi Sysmon event dựa trên Event ID của event đó. Sử dụng chính xác các tên sau trong `<if_group>`:

| Event ID | Nội dung được ghi nhận | if_group |
|---|---|---|
| 1 | Process creation | `sysmon_event1` |
| 3 | Network connection | `sysmon_event3` |
| 7 | Image/DLL loaded | `sysmon_event7` |
| 8 | CreateRemoteThread | `sysmon_event8` |
| 10 | Process access (LSASS) | `sysmon_event_10` |
| 11 | File created | `sysmon_event_11` |
| 13 | Registry value set | `sysmon_event_13` |

**Pattern:** ID có một chữ số không có dấu gạch dưới trước số. ID có hai chữ số thì có.

Để xác minh tên group trên hệ thống của bạn:
```bash
sudo grep -r "if_group" /var/ossec/ruleset/rules/ | grep sysmon | sort -u
```

---

## Bài học quan trọng: Field Names trong Rules và Dashboard

Dashboard hiển thị các field với prefix `data.`:
```
data.win.eventdata.image
data.win.eventdata.commandLine
```

**Rules KHÔNG sử dụng prefix `data.`:**
```xml
<field name="win.eventdata.image" ...>
<field name="win.eventdata.commandLine" ...>
```

Sử dụng `data.win.eventdata.*` trong rules gây ra lỗi âm thầm — rule được load mà không báo lỗi nhưng không bao giờ khớp. Luôn xác minh field names bằng cách đọc built-in rules trong `/var/ossec/ruleset/rules/`.

---

## Cách tìm Field Names chính xác

### 1. Đọc event thực tế trong dashboard
Mở rộng bất kỳ alert nào → mỗi field hiển thị đều là một field mà bạn có thể dùng để viết rule. Loại bỏ prefix `data.` khi viết rule.

### 2. Đọc built-in rules
```bash
sudo grep -r "field name" /var/ossec/ruleset/rules/0800-sysmon_id_1.xml | head -20
```
Built-in rules cho biết chính xác những field names mà Wazuh sử dụng nội bộ.

### 3. Sử dụng wazuh-logtest
```bash
sudo /var/ossec/bin/wazuh-logtest
```
Dán một raw log vào và công cụ sẽ hiển thị Phase 1 (pre-decoding), Phase 2 (decoded fields) và Phase 3 (các rule đã khớp). Sử dụng công cụ này để test rule trước khi triển khai.

### 4. Sử dụng Sigma rules làm tài liệu tham khảo
[Sigma repository](https://github.com/SigmaHQ/sigma) chứa các detection rule không phụ thuộc vendor cho gần như mọi attack technique đã biết. Sử dụng chúng để hiểu những field cần kiểm tra, sau đó chuyển đổi sang Wazuh XML.

**Quy trình chuyển đổi Sigma → Wazuh:**
```
1. Xác định attack technique (ví dụ: LSASS credential dumping)
2. Tìm Sigma rule: github.com/SigmaHQ/sigma → rules/windows/process_access/
3. Thực hiện attack trong lab, tìm raw log trong Wazuh
4. Xác nhận các field khớp với Sigma detection logic
5. Chuyển đổi Sigma condition thành một Wazuh <field> rule
6. Test bằng wazuh-logtest
7. Kích hoạt lại attack — xác nhận alert được kích hoạt
```

---

## Các Custom Rule đã viết (local_rules.xml)

### Execution
| Rule | Phát hiện | MITRE |
|---|---|---|
| 100001 | PowerShell encoded commands (`-enc`, `-EncodedCommand`) | T1059.001 |
| 100002 | LOLBins (certutil, mshta, regsvr32) tải remote content | T1218 |
| 100003 | WMI được sử dụng để execution | T1047 |
| 100004 | Shell được khởi chạy từ Office application | T1204.002 |

### Persistence
| Rule | Phát hiện | MITRE |
|---|---|---|
| 100100 | Registry `Services\*\ImagePath` bị thay đổi | T1031, T1050 |
| 100101 | Registry key `CurrentVersion\Run` bị thay đổi | T1547.001 |
| 100102 | Scheduled task được tạo bằng schtasks.exe | T1053.005 |

### Credential Access
| Rule | Phát hiện | MITRE |
|---|---|---|
| 100200 | Process truy cập LSASS (credential dumping) | T1003.001 |

### Discovery
| Rule | Phát hiện | MITRE |
|---|---|---|
| 100300 | Recon commands: whoami, net, ipconfig, systeminfo | T1082, T1033 |
| 100301 | Outbound connections đến các attack port phổ biến | T1046 |

### Defense Evasion
| Rule | Phát hiện | MITRE |
|---|---|---|
| 100400 | CreateRemoteThread (process injection) | T1055 |
| 100401 | PowerShell được khởi chạy với các evasion flag (bypass, hidden) | T1059.001 |

---

## Đã xác minh hoạt động

Đã xác nhận Rule 100300 được kích hoạt trên live event:

```
Apr 30, 2026 @ 00:44:45  DESKTOP-2M08GVE  Discovery: Recon command executed - C:\Windows\System32\whoami.exe   level:6  rule:100300
Apr 30, 2026 @ 00:44:46  DESKTOP-2M08GVE  Discovery: Recon command executed - C:\Windows\System32\net.exe      level:6  rule:100300
Apr 30, 2026 @ 00:44:46  DESKTOP-2M08GVE  Discovery: Recon command executed - C:\Windows\System32\net1.exe     level:6  rule:100300
```

---

## Các Command

```bash
# Test a rule against a raw log
sudo /var/ossec/bin/wazuh-logtest

# Edit custom rules
sudo nano /var/ossec/etc/rules/local_rules.xml

# Restart manager after rule changes
sudo systemctl restart wazuh-manager

# Check for rule load errors
sudo grep -i "error\|warning" /var/ossec/logs/ossec.log | grep "100"

# View recent alerts
sudo tail -50 /var/ossec/logs/alerts/alerts.log

# List all Sysmon rule files
sudo find /var/ossec/ruleset/rules -name "*sysmon*"
```
