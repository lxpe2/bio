import os import psutil import requests import socket import time from scapy.all import sniff



SUSPICIOUS_DOMAINS = [ "discord.com/api/webhooks", "api.telegram.org/bot", "vk.com/api/" ]



def packet_callback(packet): if packet.haslayer(socket.IP) and packet.haslayer(socket.TCP): dest_ip = packet[socket.IP].dst try: hostname = socket.gethostbyaddr(dest_ip)[0] for domain in SUSPICIOUS_DOMAINS: if domain in hostname: print(f"[ALERT] Suspicious request to {hostname} ({dest_ip})") except socket.herror: pass



def scan_processes(): print("[INFO] Scanning running processes...") suspicious_processes = [] for process in psutil.process_iter(attrs=['pid', 'name', 'exe']): try: process_info = process.info if process_info['exe'] and any(term in process_info['exe'].lower() for term in ["rat", "trojan", "malware", "keylogger"]): suspicious_processes.append(process_info) except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): pass

if suspicious_processes:
    for proc in suspicious_processes:
        print(f"[ALERT] Suspicious process detected: {proc}")
else:
    print("[INFO] No suspicious processes found.")



def check_startup(): startup_paths = [ os.path.expandvars("%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" ]

for path in startup_paths:
    if os.path.exists(path):
        for file in os.listdir(path):
            if any(ext in file for ext in [".exe", ".bat", ".vbs"]):
                print(f"[ALERT] Suspicious startup item: {file} in {path}")



def scan_system_files(): suspicious_files = [] search_paths = ["C:\Windows\System32", os.path.expanduser("~\AppData\Roaming")] for path in search_paths: if os.path.exists(path): for root, dirs, files in os.walk(path): for file in files: if any(term in file.lower() for term in ["rat", "trojan", "keylogger"]): suspicious_files.append(os.path.join(root, file))

if suspicious_files:
    for file in suspicious_files:
        print(f"[ALERT] Suspicious file found: {file}")
else:
    print("[INFO] No suspicious files detected.")

Run all checks

def main(): print("Starting RAT detection tool...") scan_processes() check_startup() scan_system_files() print("[INFO] Monitoring network traffic... Press Ctrl+C to stop.") sniff(prn=packet_callback, store=False)

if name == "main": main()

