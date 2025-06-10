import re
import threading
import time

# Define NMAP_AVAILABLE at the module level first
NMAP_AVAILABLE = False

# Try importing nmap, gracefully handle if not installed
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    pass
    
def show_progress(current, total, bar_length=50):
    """Display a progress bar for the port scanning process."""
    percent = float(current) * 100 / total
    arrow = '-' * int(percent/100 * bar_length - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    print(f'\rProgress: [{arrow + spaces}] {percent:.2f}%', end='')

def port_scanner():
    """Run a port scanner to detect open ports on a target IP."""
    global NMAP_AVAILABLE

    if not NMAP_AVAILABLE:
        print("The python-nmap module is not installed.")
        install_choice = input("Would you like to install it now? (y/n): ").lower()
        if install_choice == 'y':
            try:
                import pip
                pip.main(['install', 'python-nmap'])
                print("python-nmap installed successfully.")
                try:
                    import nmap
                    NMAP_AVAILABLE = True
                except ImportError:
                    print("Failed to import nmap after installation.")
                    return "Unable to run port scanner: Failed to import nmap module after installation."
            except Exception as e:
                print(f"Failed to install python-nmap: {e}")
                return "Unable to run port scanner: Failed to install required module."
        else:
            return "Port scanner requires the python-nmap module. Installation was declined."

    import nmap
    ip_add_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b"
    )
    port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)")

    # Ask user to input the IP address they want to scan
    while True:
        ip_add_entered = input("\nPlease enter the IP address that you want to scan: ")
        if ip_add_pattern.search(ip_add_entered):
            print(f"{ip_add_entered} is a valid IP address")
            break
        else:
            print(f"{ip_add_entered} is not a valid IP address")

    # Ask user for the port range
    while True:
        print("Please enter the range of ports you want to scan in format: <int>-<int> (ex: 20-100)")
        port_range = input("Enter port range: ")
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        if port_range_valid:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            if 0 <= port_min <= 65535 and port_min <= port_max <= 65535:
                break
            else:
                print("Invalid port range. Ports must be between 0 and 65535, and min must be <= max.")
        else:
            print("Invalid port range format. Please use format like '20-100'.")

    try:
        nm = nmap.PortScanner()
        version = nm.nmap_version()
        print(f"nmap version: {version}")
    except Exception as e:
        return f"Failed to initialize scanner: {e}"

    print(f"\nScanning {ip_add_entered} for open ports in range {port_min}-{port_max}...")

    open_ports = []
    total_ports = port_max - port_min + 1
    current_port = 0
    progress_lock = threading.Lock()

    def scan_port(port):
        nonlocal current_port
        try:
            result = nm.scan(ip_add_entered, str(port), arguments="-sS -Pn")
            if ip_add_entered in result['scan']:
                tcp_info = result['scan'][ip_add_entered].get('tcp', {})
                if port in tcp_info and tcp_info[port]['state'] == 'open':
                    service = tcp_info[port].get('name', 'unknown')
                    product = tcp_info[port].get('product', '')
                    version = tcp_info[port].get('version', '')
                    service_info = f"{service}"
                    if product:
                        service_info += f" ({product}"
                        if version:
                            service_info += f" {version}"
                        service_info += ")"
                    open_ports.append((port, service_info))
                    print(f"\nPort {port} is open - {service_info}")
        except Exception as e:
            print(f"\nError scanning port {port}: {e}")
        finally:
            with progress_lock:
                current_port += 1
                show_progress(current_port, total_ports)

    port_step = min(20, total_ports)
    for i in range(port_min, port_max + 1, port_step):
        threads = []
        batch_end = min(i + port_step, port_max + 1)
        for port in range(i, batch_end):
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    print("\n\nScan completed!")

    if open_ports:
        print("\nSummary of open ports:")
        print("---------------------")
        for port, service in sorted(open_ports):
            print(f"Port {port}: {service}")
    else:
        print("No open ports were found in the specified range.")

    return f"Port scan complete on {ip_add_entered}. Found {len(open_ports)} open ports."
if __name__ == "__main__":
    # This allows the module to be run directly
    result = port_scanner()
    print(result)