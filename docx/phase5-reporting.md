# Phase 5 — Reporting

## Tổng quan

Reporting chuyển đổi raw alert data thành actionable intelligence. SOC analyst không chỉ thực hiện detection — họ còn truyền đạt finding đến stakeholder, theo dõi security posture theo thời gian và cung cấp evidence cho các remediation decision.

Phase 5 xây dựng hai dashboard trong OpenSearch Dashboards (visualisation layer tích hợp sẵn của Wazuh):

1. **Attack Overview** — điều gì đã xảy ra, xảy ra khi nào và những MITRE technique nào đã được sử dụng
2. **Security Posture** — vulnerability exposure và compliance failure trên victim machine

---

## Cách Dashboard hoạt động trong Wazuh

Wazuh lưu trữ tất cả alert trong OpenSearch index (`wazuh-alerts-*`). OpenSearch Dashboards cung cấp một visualisation layer ở phía trên — cùng engine với Kibana. Mọi field trong alert đều có thể query và aggregate.

Dashboard được xây dựng từ các **visualisation** riêng lẻ — chart, table và metric, mỗi thành phần query index một cách độc lập. Nhiều visualisation được ghim vào một canvas và dùng chung time range filter.

**Các khái niệm chính:**
- **DQL filter** — giới hạn một visualisation vào các rule, agent hoặc field value cụ thể
- **Terms aggregation** — nhóm kết quả theo field value (ví dụ: rule.id, MITRE tactic)
- **Date histogram** — biểu diễn event theo thời gian
- **Time range** — tất cả visualisation trên dashboard sử dụng chung một window

---

## Dashboard 1 — Attack Overview

**Mục đích:** Hiển thị toàn cảnh attack — attack xảy ra khi nào, MITRE tactic nào đã được sử dụng, tổng alert volume và những rule nào đã kích hoạt nhiều nhất.

![Attack Overview Dashboard](../assets/dashboard.png)

### Các Panel

**Attack Timeline — Alerts by Severity**
- Type: Vertical Bar
- X-axis: Date Histogram trên `timestamp` (theo giờ)
- Split series: `rule.level` (tô màu theo severity)
- Spike tại 2026-05-05 00:00 là full kill chain test — brute force, recon và persistence chạy nối tiếp nhau. Các attack session hiển thị rõ ràng dưới dạng spike trên một baseline phẳng.

**MITRE Tactics Distribution**
- Type: Pie / Donut
- Split slices: `rule.mitre.tactic`
- Cho thấy Defense Evasion là tactic chiếm ưu thế, tiếp theo là Privilege Escalation, Initial Access và Persistence — phản ánh trực tiếp các attack scenario được thực hiện trong Phase 3.

**Total Alerts — 324**
- Type: Metric
- Số lượng tất cả alert trong time window
- Cung cấp cho analyst một headline number cho reporting period

**Correlation Rules Fired — 12**
- Type: Metric
- Filter: `rule.id: 100500 or rule.id: 100600 or rule.id: 100601`
- Chỉ đếm các correlation alert có độ tin cậy cao — brute force, recon chain, persistence chain. Tách signal khỏi noise.

**Top Rules by Alert Count**
- Type: Data Table
- Split rows: `rule.id` → `rule.description`
- Cho biết những rule nào kích hoạt thường xuyên nhất — hữu ích để xác định cả attack pattern lẫn noise còn lại

---

## Dashboard 2 — Security Posture

**Mục đích:** Hiển thị security health của victim machine — có bao nhiêu vulnerability và những compliance check nào đang thất bại.

![Security Posture Dashboard](../assets/dashboard2.png)

### Các Panel

**Active CVEs — Windows 10**
- Type: Data Table
- Filter: `rule.id: 23505`, Last 7 days
- Split rows: `data.vulnerability.cve`
- Liệt kê tất cả high-severity CVE đang active trên Windows 10 cùng link đến Microsoft Security Response Center (MSRC) — có thể xử lý trực tiếp trong patch management

**Total CVEs Detected — 457**
- Type: Metric
- Filter: `rule.id: 23505`
- 457 high severity CVE trên một Windows 10 VM chưa được patch — headline number cho vulnerability report

**Top SCA Failures**
- Type: Horizontal Bar
- Filter: `rule.id: 19007`
- Field: `data.sca.check.title`
- Hiển thị các compliance check thất bại nhiều nhất — tất cả đều là SSH-related configuration failure (PermitEmptyPasswords, PermitUserEnvironment, UsePAM, ClientAliveInterval, v.v.)
- Trong một environment thực tế, chúng sẽ được đưa trực tiếp vào hardening backlog

**SCA Failed Checks — 420**
- Type: Metric
- Filter: `rule.id: 19007`
- 420 Security Configuration Assessment failure — compliance gap trên tất cả monitored policy

**SCA Check Results Distribution**
- Type: Pie
- Field: `data.sca.check.result`
- Hiển thị tỷ lệ giữa failed, passed và not-applicable check — cung cấp overall compliance score theo tỷ lệ thay vì một con số thô

---

## Dữ liệu cho thấy điều gì

### Attack posture
- Tổng cộng 324 alert trong suốt thời gian vận hành lab
- 12 correlation alert có độ tin cậy cao (brute force + recon + persistence chain)
- Defense Evasion là MITRE tactic chiếm ưu thế — phản ánh PowerShell evasion flag và các process injection attempt

### Vulnerability posture
- 457 high severity CVE trên Windows 10
- Tất cả đều thuộc series CVE-2025-* — các Microsoft vulnerability gần đây trên một machine chưa được patch
- Remediation priority: áp dụng Windows update

### Compliance posture
- 420 SCA check failure
- Các failure hàng đầu là SSH configuration check — Ubuntu Wazuh manager có thiết lập SSH sai cấu hình
- Những nội dung này được đưa vào hardening checklist cho server

---

## Xây dựng các Dashboard này

Truy cập `https://192.168.56.10/app/dashboards` và nhấp vào **Create new dashboard**.

Mỗi visualisation được tạo thông qua **Create new** → chọn type → cấu hình tab Data → save → thêm vào canvas.

### Các DQL filter

```
# Attack correlation rules only
rule.id: 100500 or rule.id: 100600 or rule.id: 100601

# Vulnerability scanner hits
rule.id: 23505

# SCA compliance failures
rule.id: 19007

# Specific agent only
agent.name: DESKTOP-2M08GVE

# High severity only
rule.level >= 10
```

### Lưu ý về Time range
Dữ liệu Vulnerability (23505) và SCA (19007) được tạo trong quá trình thiết lập lab ban đầu. Đặt time range thành **Last 7 days** hoặc **Last 30 days** để lấy dữ liệu — giá trị mặc định Last 24 hours sẽ không trả về kết quả.
