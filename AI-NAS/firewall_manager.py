import subprocess
import os
import json
import time
import re
from datetime import datetime

class FirewallManager:
    """Class for managing Windows Firewall rules."""
    
    def __init__(self):
        """Initialize the firewall manager."""
        self.config_file = "firewall_config.json"
        self.rules = self._load_rules()
    
    def _load_rules(self):
        """Load custom firewall rules from config file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                return data.get('rules', [])
            else:
                # Create empty rules file
                with open(self.config_file, 'w') as f:
                    json.dump({'rules': []}, f, indent=4)
                return []
        except Exception as e:
            print(f"Error loading firewall rules: {e}")
            return []
    
    def _save_rules(self):
        """Save custom firewall rules to config file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump({'rules': self.rules}, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving firewall rules: {e}")
            return False
    
    def get_status(self):
        """Get detailed firewall status information."""
        try:
            # Get current profile
            current_profile = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'currentprofile'],
                capture_output=True,
                text=True
            )
            
            # Get firewall rules count
            rule_count = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', 'status=enabled'],
                capture_output=True,
                text=True
            )
            
            # Parse rule count from output
            rules_count_match = re.search(r'Ok.\s+Rules:\s+(\d+)', rule_count.stdout)
            rules_count = rules_count_match.group(1) if rules_count_match else "Unknown"
            
            # Get custom rules count
            custom_rules_count = len(self.rules)
            
            # Format the output
            status_info = "Windows Firewall Status:\n"
            status_info += "------------------------\n"
            
            # Check if firewall is enabled
            if "State                                 ON" in current_profile.stdout:
                status_info += "Status: Enabled\n"
            else:
                status_info += "Status: Disabled\n"
                
            status_info += f"Enabled Rules: {rules_count}\n"
            status_info += f"Custom Rules: {custom_rules_count}\n"
            status_info += "\nCurrent Profile Settings:\n"
            
            # Add profile settings
            for line in current_profile.stdout.splitlines():
                if ":" in line:
                    status_info += f"{line.strip()}\n"
            
            return status_info
        except Exception as e:
            return f"Error getting firewall status: {e}"
    
    def set_firewall_state(self, enable=True):
        """Enable or disable Windows Firewall."""
        try:
            state = "on" if enable else "off"
            
            # Run netsh command to change firewall state
            result = subprocess.run(
                ['netsh', 'advfirewall', 'set', 'currentprofile', 'state', state],
                capture_output=True,
                text=True
            )
            
            if "Ok." in result.stdout:
                return f"Windows Firewall has been turned {state}."
            else:
                return f"Failed to change firewall state. Error: {result.stderr}"
        except Exception as e:
            return f"Error changing firewall state: {e}"
    
    def add_rule(self, program_path, name=None, action="allow", direction="both"):
        """Add a firewall rule for a specific program."""
        try:
            # Check if program exists
            if not os.path.isfile(program_path) and not program_path.lower().endswith('.exe'):
                # Try to find the executable
                if not program_path.lower().endswith('.exe'):
                    program_path += '.exe'
                    
                # Common locations to search
                common_locations = [
                    os.path.join(os.environ.get("ProgramFiles", ""), program_path),
                    os.path.join(os.environ.get("ProgramFiles(x86)", ""), program_path),
                    os.path.join(os.environ.get("SystemRoot", ""), program_path),
                    os.path.join(os.environ.get("SystemRoot", ""), "System32", program_path)
                ]
                
                for location in common_locations:
                    if os.path.isfile(location):
                        program_path = location
                        break
                else:
                    return f"Could not find program: {program_path}"
            
            # Generate rule name if not provided
            if not name:
                program_name = os.path.basename(program_path).replace('.exe', '')
                rule_name = f"{program_name}_rule_{int(time.time())}"
            else:
                rule_name = name
            
            success = True
            
            # Handle different directions
            if direction == "both" or direction == "in":
                # Add inbound rule
                inbound_result = subprocess.run(
                    [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name="{rule_name}_in"',
                        f'program="{program_path}"',
                        'dir=in',
                        f'action={action}',
                        'enable=yes'
                    ],
                    capture_output=True,
                    text=True
                )
                
                if "Ok." not in inbound_result.stdout:
                    success = False
            
            if direction == "both" or direction == "out":
                # Add outbound rule
                outbound_result = subprocess.run(
                    [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name="{rule_name}_out"',
                        f'program="{program_path}"',
                        'dir=out',
                        f'action={action}',
                        'enable=yes'
                    ],
                    capture_output=True,
                    text=True
                )
                
                if "Ok." not in outbound_result.stdout:
                    success = False
            
            # Check if rules were added successfully
            if success:
                # Add to custom rules list
                self.rules.append({
                    'name': rule_name,
                    'program': program_path,
                    'action': action,
                    'direction': direction,
                    'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                self._save_rules()
                
                action_text = "allowed" if action == "allow" else "blocked"
                return f"Firewall rule added: {os.path.basename(program_path)} is now {action_text}."
            else:
                return f"Failed to add firewall rule. Please check the program path and try again."
        except Exception as e:
            return f"Error adding firewall rule: {e}"
    
    def remove_rule(self, rule_name):
        """Remove a firewall rule by name."""
        try:
            found = False
            
            # Check if rule exists in our custom rules
            for rule in self.rules:
                if rule['name'] == rule_name:
                    found = True
                    break
            
            if not found:
                return f"Rule '{rule_name}' not found."
            
            # Remove inbound rule
            inbound_result = subprocess.run(
                [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name="{rule_name}_in"'
                ],
                capture_output=True,
                text=True
            )
            
            # Remove outbound rule
            outbound_result = subprocess.run(
                [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name="{rule_name}_out"'
                ],
                capture_output=True,
                text=True
            )
            
            # Remove from custom rules list
            self.rules = [rule for rule in self.rules if rule['name'] != rule_name]
            self._save_rules()
            
            return f"Firewall rule '{rule_name}' removed."
        except Exception as e:
            return f"Error removing firewall rule: {e}"
    
    def block_ip(self, ip_address, name=None):
        """Block an IP address using the firewall."""
        try:
            # Generate rule name if not provided
            if not name:
                rule_name = f"Block_{ip_address}_{int(time.time())}"
            else:
                rule_name = name
            
            # Add inbound rule to block IP
            result = subprocess.run(
                [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name="{rule_name}"',
                    f'remoteip={ip_address}',
                    'dir=in',
                    'action=block',
                    'enable=yes'
                ],
                capture_output=True,
                text=True
            )
            
            if "Ok." in result.stdout:
                # Add to custom rules list
                self.rules.append({
                    'name': rule_name,
                    'ip': ip_address,
                    'type': 'block_ip',
                    'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                self._save_rules()
                
                return f"IP address {ip_address} has been blocked."
            else:
                return f"Failed to block IP address. Error: {result.stderr}"
        except Exception as e:
            return f"Error blocking IP address: {e}"
    
    def list_rules(self):
        """List all custom firewall rules."""
        if not self.rules:
            return "No custom firewall rules found."
        
        output = "Custom Firewall Rules:\n"
        output += "----------------------\n"
        
        for i, rule in enumerate(self.rules, 1):
            if 'type' in rule and rule['type'] == 'block_ip':
                output += f"{i}. {rule['name']} - Blocks IP: {rule['ip']} (Created: {rule['created']})\n"
            else:
                direction = rule.get('direction', 'both')
                action = rule.get('action', 'allow')
                output += f"{i}. {rule['name']} - Program: {rule['program']} (Direction: {direction}, Action: {action}, Created: {rule['created']})\n"
        
        return output

def firewall_manager_main():
    """Main function for the firewall manager."""
    firewall = FirewallManager()
    
    print("\nWindows Firewall Manager")
    print("======================")
    print("1. Check firewall status")
    print("2. Enable firewall")
    print("3. Disable firewall")
    print("4. Add rule for program")
    print("5. Block IP address")
    print("6. List custom rules")
    print("7. Remove rule")
    print("8. Exit")
    
    while True:
        choice = input("\nEnter your choice (1-8): ")
        
        if choice == '1':
            print(firewall.get_status())
        
        elif choice == '2':
            result = firewall.set_firewall_state(True)
            print(result)
        
        elif choice == '3':
            result = firewall.set_firewall_state(False)
            print(result)
        
        elif choice == '4':
            program = input("Enter program path (or name): ")
            action = input("Allow or block? (allow/block) [default: allow]: ").lower() or "allow"
            direction = input("Direction (in/out/both) [default: both]: ").lower() or "both"
            
            if action not in ["allow", "block"]:
                action = "allow"
            
            if direction not in ["in", "out", "both"]:
                direction = "both"
            
            result = firewall.add_rule(program, action=action, direction=direction)
            print(result)
        
        elif choice == '5':
            ip = input("Enter IP address to block: ")
            result = firewall.block_ip(ip)
            print(result)
        
        elif choice == '6':
            print(firewall.list_rules())
        
        elif choice == '7':
            # First show the list of rules
            print(firewall.list_rules())
            rule_name = input("Enter the name of the rule to remove: ")
            result = firewall.remove_rule(rule_name)
            print(result)
        
        elif choice == '8':
            print("Exiting Firewall Manager.")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 8.")

if __name__ == "__main__":
    # This allows the module to be run directly
    firewall_manager_main()