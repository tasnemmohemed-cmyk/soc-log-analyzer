import pandas as pd
import datetime
raw_logs = [
    {"timestamp": "2026-11-02 10:00:01", "ip": "192.168.1.50", "user": "admin", "status": "FAILED", "event_id": 4625},
    {"timestamp": "2026-11-02 10:00:03", "ip": "192.168.1.50", "user": "admin", "status": "FAILED", "event_id": 4625},
    {"timestamp": "2026-11-02 10:00:05", "ip": "192.168.1.50", "user": "admin", "status": "FAILED", "event_id": 4625},
    {"timestamp": "2026-11-02 10:00:08", "ip": "192.168.1.50", "user": "admin", "status": "FAILED", "event_id": 4625},
    {"timestamp": "2026-11-02 10:00:12", "ip": "192.168.1.50", "user": "admin", "status": "SUCCESS", "event_id": 4624},
    {"timestamp": "2026-11-02 10:05:00", "ip": "10.0.0.12", "user": "sara", "status": "FAILED", "event_id": 4625},
    {"timestamp": "2026-11-02 10:10:15", "ip": "172.16.0.99", "user": "root", "status": "FAILED", "event_id": 4625},
    {"timestamp": "2026-11-02 10:10:18", "ip": "172.16.0.99", "user": "root", "status": "FAILED", "event_id": 4625},
    {"timestamp": "2026-11-02 10:10:22", "ip": "172.16.0.99", "user": "root", "status": "FAILED", "event_id": 4625},
]



df = pd.DataFrame(raw_logs)

# 2. محرك كشف التهديدات (Threat Detection Engine)
THRESHOLD = 3  # حد الخطورة: 3 محاولات فاشلة أو أكثر

# فلترة المحاولات الفاشلة
failed_attempts = df[df['status'] == 'FAILED']

# تجميع وحساب عدد المحاولات لكل IP
attack_summary = failed_attempts.groupby(['ip', 'user']).size().reset_index(name='failed_count')

# تحديد الـ IPs ذات الخطورة العالية (Brute-Force Suspects)
alerts = attack_summary[attack_summary['failed_count'] >= THRESHOLD].copy()
alerts['threat_level'] = 'CRITICAL (Possible Brute-Force)'

# 3. طباعة التقرير الأمني الاحترافي في الـ Terminal
print("="*60)
print(" 🛡️ SOC SECURITY THREAT ANALYSIS REPORT 🛡️ ")
print("="*60)
print(f"Total Logs Analyzed: {len(df)}")
print(f"Total Failed Logins: {len(failed_attempts)}")
print("-"*60)
print("🚨 DETECTED SECURITY ALERTS:")
print(alerts.to_string(index=False))
print("="*60)

# 4. تصدير التقرير تلقائياً لملف CSV لاستخدامه من قبل فريق الـ SOC
alerts.to_csv('high_risk_ips.csv', index=False)
print("\n[+] Success: High-risk threat report generated: 'high_risk_ips.csv'")

input("\nPress Enter to close...")


input("\n close")
