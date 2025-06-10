import os
import hashlib
import psutil
import re
import threading
import time
import json
import subprocess
import socket
import shutil
import stat
import platform



class ThreatDetector:
    """Class for detecting threats and malware on the system."""
    
    def __init__(self):
        """Initialize the threat detector."""
        self.threats_found = []
        self.lock = threading.Lock()  # For thread safety
        self.common_malware_extensions = [
            ".exe", ".dll", ".ocx", ".sys", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1"
        ]
        
        # Define suspicious process names
        self.suspicious_processes = [
            "notminer", "crypto", "backdoor", "keylogger", "trojan", 
            "ransomware", "worm", "spyware", "rootkit"
        ]
        
        # Known malicious IP addresses for network check
        self.malicious_ips = [
            "185.159.82.59", "45.94.47.66", "89.238.150.154",
            "192.99.142.235", "104.244.75.225", "185.141.63.120",
            "176.119.7.15", "193.169.255.61"  # These are examples
        ]
        
        # Load custom malicious IPs if file exists
        self._load_custom_ips()
        
        # Directories to scan for quick check
        self.high_risk_directories = [
            os.path.join(os.environ.get("TEMP", "")),
            os.path.join(os.environ.get("APPDATA", ""), "Temp"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp")
        ]
    
    def _load_custom_ips(self):
        """Load custom malicious IP addresses from file if it exists."""
        try:
            if os.path.exists("malicious_ips.json"):
                with open("malicious_ips.json", "r") as f:
                    data = json.load(f)
                    self.malicious_ips.extend(data.get("ips", []))
        except Exception as e:
            print(f"Error loading custom malicious IPs: {e}")
    
    def quick_scan(self):
        """Perform a quick scan for obvious threats."""
        print("Starting quick threat scan...")
        self.threats_found = []
        
        # Run scans in parallel threads
        scan_threads = [
            threading.Thread(target=self._scan_suspicious_processes),
            threading.Thread(target=self._scan_network_connections),
            threading.Thread(target=self._scan_temp_directories)
        ]
        
        # Start all threads
        for thread in scan_threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in scan_threads:
            thread.join()
        
        # Return the results
        if self.threats_found:
            return {
                "status": "threats_detected",
                "count": len(self.threats_found),
                "threats": self.threats_found
            }
        else:
            return {
                "status": "clean",
                "message": "No immediate threats detected"
            }
    
    def _scan_suspicious_processes(self):
        """Scan running processes for suspicious activity."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    # Check if process name matches any suspicious process
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                    
                    if any(susp in proc_name for susp in self.suspicious_processes):
                        with self.lock:
                            self.threats_found.append({
                                'type': 'suspicious_process',
                                'name': proc.info['name'],
                                'pid': proc.info['pid'],
                                'user': proc.info['username'],
                                'command': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                            })
                    
                    # Check for processes running from temp directories
                    try:
                        if proc.exe():
                            exe_path = proc.exe().lower()
                            if "\\temp\\" in exe_path or "\\tmp\\" in exe_path:
                                with self.lock:
                                    self.threats_found.append({
                                        'type': 'suspicious_location',
                                        'name': proc.info['name'],
                                        'pid': proc.info['pid'],
                                        'path': proc.exe()
                                    })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            print(f"Error scanning processes: {e}")
    
    def _scan_network_connections(self):
        """Scan network connections for malicious activity."""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                try:
                    # Skip connections with no remote address
                    if not conn.raddr:
                        continue
                    
                    remote_ip = conn.raddr.ip
                    
                    # Check if connected to a known malicious IP
                    if remote_ip in self.malicious_ips:
                        try:
                            process = psutil.Process(conn.pid) if conn.pid else None
                            proc_name = process.name() if process else "Unknown"
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "Unknown"
                        
                        with self.lock:
                            self.threats_found.append({
                                'type': 'malicious_connection',
                                'remote_ip': remote_ip,
                                'remote_port': conn.raddr.port,
                                'local_port': conn.laddr.port,
                                'process': proc_name,
                                'pid': conn.pid
                            })
                except Exception:
                    pass
        except Exception as e:
            print(f"Error scanning network connections: {e}")
    
    def _scan_temp_directories(self):
        """Scan temporary directories for suspicious files."""
        try:
            for directory in self.high_risk_directories:
                if not os.path.exists(directory):
                    continue
                
                for root, _, files in os.walk(directory):
                    for file in files:
                        # Check file extension
                        if any(file.lower().endswith(ext) for ext in self.common_malware_extensions):
                            file_path = os.path.join(root, file)
                            
                            # Skip very large files for quick scan
                            try:
                                if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB
                                    continue
                                
                                # Check file for common malware patterns
                                if self._quick_check_file(file_path):
                                    with self.lock:
                                        self.threats_found.append({
                                            'type': 'suspicious_file',
                                            'path': file_path,
                                            'name': file
                                        })
                            except Exception:
                                # File might be in use or inaccessible
                                pass
        except Exception as e:
            print(f"Error scanning temp directories: {e}")
    
    def _quick_check_file(self, file_path):
        """Quick check of a file for obvious malware characteristics."""
        try:
            suspicious_strings = [
                b"powershell -enc", 
                b"cmd.exe /c", 
                b"rundll32", 
                b"regsvr32",
                b"certutil -decode",
                b".Download",
                b"WScript.Shell",
                b"CreateObject"
            ]
            
            # Read the first 4KB of the file
            with open(file_path, "rb") as f:
                data = f.read(4096)
            
            # Check for suspicious strings
            for sus_str in suspicious_strings:
                if sus_str in data:
                    return True
            
            return False
        except Exception:
            return False
    
    def get_threat_summary(self):
        """Generate a user-friendly summary of detected threats."""
        if not self.threats_found:
            return "No threats detected during the quick scan."
        
        summary = f"Found {len(self.threats_found)} potential threats:\n\n"
        
        for i, threat in enumerate(self.threats_found, 1):
            if threat['type'] == 'suspicious_process':
                summary += f"{i}. Suspicious Process: {threat['name']} (PID: {threat['pid']})\n"
            elif threat['type'] == 'suspicious_location':
                summary += f"{i}. Suspicious Location: {threat['name']} running from {threat['path']}\n"
            elif threat['type'] == 'malicious_connection':
                summary += f"{i}. Malicious Connection: {threat['process']} connected to {threat['remote_ip']}:{threat['remote_port']}\n"
            elif threat['type'] == 'suspicious_file':
                summary += f"{i}. Suspicious File: {threat['name']} at {threat['path']}\n"
        
        summary += "\nRecommendation: Run your antivirus software for a full system scan."
        return summary
    
    
    def respond_to_threats(self):
       
        actions_taken = []

        for threat in self.threats_found:
            if threat['type'] == 'suspicious_process':
                try:
                    process = psutil.Process(threat['pid'])
                    process.terminate()
                    actions_taken.append(f"Terminated suspicious process: {threat['name']}")
                except Exception as e:
                    actions_taken.append(f"Failed to terminate process {threat['name']}: {e}")
            
            elif threat['type'] == 'suspicious_file':
                try:
                    # Create threats folder if it doesn't exist
                    threats_dir = "threats"
                    os.makedirs(threats_dir, exist_ok=True)

                    original_path = threat['path']
                    base_name = os.path.basename(original_path)
                    name_without_ext = os.path.splitext(base_name)[0]
                    new_filename = f"{int(time.time())}_{name_without_ext}.txt"
                    destination_path = os.path.join(threats_dir, new_filename)

                    # Copy file to threats folder with .txt extension
                    shutil.copy2(original_path, destination_path)
                    actions_taken.append(f"Copied suspicious file as .txt to threats folder: {new_filename}")

                    # Remove execution permission or neuter file
                    if platform.system() == "Windows":
                        try:
                            # Remove all execution permission using icacls
                            subprocess.run(['icacls', original_path, '/deny', 'Everyone:(X)'], check=True)
                            actions_taken.append(f"Removed execute permission from: {base_name}")
                        except Exception as e:
                            actions_taken.append(f"Failed to change file permissions on Windows: {e}")
                    else:
                        # On Linux/Mac, remove execute bit
                        os.chmod(original_path, os.stat(original_path).st_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)
                        actions_taken.append(f"Removed execute permission from: {base_name}")
                except Exception as e:
                    actions_taken.append(f"Failed to process suspicious file {threat['name']}: {e}")

        return actions_taken

def main():
    """Run a standalone threat detection scan."""
    detector = ThreatDetector()
    results = detector.quick_scan()
    
    if results["status"] == "threats_detected":
        print(detector.get_threat_summary())
        
        # Ask if user wants to respond to threats
        response = input("Do you want to respond to these threats? (y/n): ")
        if response.lower() == 'y':
            actions = detector.respond_to_threats()
            for action in actions:
                print(action)
    else:
        print("No immediate threats detected.")

if __name__ == "__main__":
    # This allows the module to be run directly
    main()