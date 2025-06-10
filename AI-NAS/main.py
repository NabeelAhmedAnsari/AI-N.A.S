import os
import speech_recognition as sr
import pyttsx3
import subprocess
import google.generativeai as genai
import winreg
import glob
import psutil
import re
import threading
import time
import port_scanner
import firewall_manager
import threat_detector

# Initialize Google Gemini API 
genai.configure(api_key="AIzaSyCtnmuNmg9Sv9sbpByeDD7Zphvzwii4P4A")  
# Initialize Text-to-Speech engine
engine = pyttsx3.init()

# Initialize firewall manager
fw = firewall_manager.FirewallManager()

# Initialize threat detector
td = threat_detector.ThreatDetector()

def speak(text):
    """Convert text to speech."""
    engine.say(text)
    engine.runAndWait()

def listen():
    """Capture voice input and convert to text."""
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        speak("I'm listening...")
        try:
            audio = recognizer.listen(source, timeout=5, phrase_time_limit=5)
            command = recognizer.recognize_google(audio)
            return command.lower()
        except sr.UnknownValueError:
            return "Sorry, I couldn't understand that."
        except sr.RequestError:
            return "Network error. Please check your connection."

def ai_response(prompt):
    """Generate AI response using Google Gemini API."""
    try:
        # Use Gemini model to generate response
        model = genai.GenerativeModel("gemini-1.5-flash")  # Use the appropriate Gemini model
        response = model.generate_content(prompt)
        return response.text  # Return the generated text
    except Exception as e:
        return f"Error: {e}"

def get_installed_apps():
    """Get a dictionary of installed applications from the Windows registry."""
    app_paths = {}
    
    # Check common registry locations for installed programs
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    
    for reg_path in registry_paths:
        try:
            registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(registry, reg_path)
            
            # Enumerate subkeys
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    app_name = winreg.EnumKey(key, i)
                    app_key = winreg.OpenKey(key, app_name)
                    
                    try:
                        path_value = winreg.QueryValueEx(app_key, "")
                        if path_value and path_value[0].endswith(".exe"):
                            app_paths[os.path.basename(path_value[0]).replace(".exe", "").lower()] = path_value[0]
                    except:
                        pass
                        
                    try:
                        display_name = winreg.QueryValueEx(app_key, "DisplayName")[0]
                        path = winreg.QueryValueEx(app_key, "InstallLocation")[0]
                        if path and os.path.exists(path):
                            # Look for executable in the install directory
                            exes = glob.glob(os.path.join(path, "*.exe"))
                            if exes:
                                app_paths[display_name.lower()] = exes[0]
                                app_paths[os.path.basename(exes[0]).replace(".exe", "").lower()] = exes[0]
                    except:
                        pass
                        
                    winreg.CloseKey(app_key)
                except:
                    continue
            
            winreg.CloseKey(key)
        except:
            continue
    
    # Add common applications from Start Menu
    start_menu_paths = [
        os.path.join(os.environ["PROGRAMDATA"], "Microsoft", "Windows", "Start Menu", "Programs"),
        os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs")
    ]
    
    for start_path in start_menu_paths:
        if os.path.exists(start_path):
            for root, dirs, files in os.walk(start_path):
                for file in files:
                    if file.endswith(".lnk"):
                        app_name = os.path.splitext(file)[0].lower()
                        app_paths[app_name] = os.path.join(root, file)
    
    return app_paths

def find_file_or_folder(name):
    """Find a file or folder on the system using more efficient methods."""
    # Try to find exact matches first in common locations
    common_locations = [
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~"),
        os.path.expanduser("~\\OneDrive\\Desktop"),
        os.path.expanduser("~\\OneDrive\\Documents")
    ]
    
    # Check if name has an extension, if not, add common ones to search
    if "." not in name:
        extensions = [".txt", ".pdf", ".docx", ".xlsx", ".pptx", ".jpg", ".png"]
        possible_file_names = [name + ext for ext in extensions] + [name]
    else:
        possible_file_names = [name]
    
    # First search for the exact folder name (fast)
    for location in common_locations:
        if os.path.exists(location):
            potential_folder = os.path.join(location, name)
            if os.path.isdir(potential_folder):
                return potential_folder, "folder"
            
            # Also check for case-insensitive folder match
            for item in os.listdir(location):
                if item.lower() == name.lower() and os.path.isdir(os.path.join(location, item)):
                    return os.path.join(location, item), "folder"
    
    # Then search for files
    for location in common_locations:
        if os.path.exists(location):
            for root, dirs, files in os.walk(location):
                for file in files:
                    for possible_name in possible_file_names:
                        if file.lower() == possible_name.lower():
                            return os.path.join(root, file), "file"
    
    # Ask user if they want to perform a deeper search
    print(f"'{name}' not found in common locations.")
    deep_search = input("Would you like to perform a deeper search? (y/n): ").lower()
    
    if deep_search == 'y':
        speak("Searching for your file or folder. This might take a moment.")
        print("Searching system drives (this may take some time)...")
        
        # Get all drives
        drives = [d.device for d in psutil.disk_partitions() if 'fixed' in d.opts]
        
        for drive in drives:
            try:
                # First check for folder matches
                for root, dirs, _ in os.walk(drive):
                    for dir_name in dirs:
                        if dir_name.lower() == name.lower():
                            return os.path.join(root, dir_name), "folder"
                            
                # Then check for file matches using glob
                for possible_name in possible_file_names:
                    matches = glob.glob(f"{drive}\\**\\{possible_name}", recursive=True)
                    if matches:
                        return matches[0], "file"
            except Exception as e:
                print(f"Error searching drive {drive}: {e}")
    
    return None, None

def execute_command(command):
    """Perform system-level commands with improved file and folder handling."""
    # Handle threat scanning command
    if "scan threats" in command or "detect threats" in command or "threat scan" in command:
        print("Starting threat detection scan...")
        results = td.quick_scan()
        if results["status"] == "threats_detected":
            summary = td.get_threat_summary()
            
            # Ask if user wants to respond to threats
            print(summary)
            response = input("Do you want to respond to these threats? (y/n): ")
            if response.lower() == 'y':
                actions = td.respond_to_threats()
                action_text = "\n".join(actions)
                return f"{summary}\n\nActions taken:\n{action_text}"
            return summary
        else:
            return "No immediate threats detected."
    
    # Handle port scanning command
    elif "scan ports" in command or "port scan" in command:
        return port_scanner.port_scanner()
    
    # Firewall commands
    elif "firewall" in command:
        # Check firewall status
        if "status" in command:
            return fw.get_status()
        # Enable firewall
        elif "enable" in command or "turn on" in command:
            return fw.set_firewall_state(True)
        # Disable firewall
        elif "disable" in command or "turn off" in command:
            return fw.set_firewall_state(False)
        # Add firewall rule
        elif "add rule" in command or "create rule" in command:
            # Check if the command specifies a program
            if "for" in command:
                parts = command.split("for", 1)
                if len(parts) > 1:
                    program = parts[1].strip()
                    # Check if we need to allow or block
                    action = "allow"  # Default action
                    if "block" in parts[0]:
                        action = "block"
                    return fw.add_rule(program, action=action)
                else:
                    return "Please specify a program for the firewall rule."
            else:
                program = input("Enter program path or name: ")
                action = input("Allow or block? (allow/block) [default: allow]: ").lower() or "allow"
                if action not in ["allow", "block"]:
                    action = "allow"
                return fw.add_rule(program, action=action)
        # Block IP address
        elif "block ip" in command:
            # Check if IP is provided in command
            ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            match = ip_pattern.search(command)
            if match:
                ip = match.group(1)
                return fw.block_ip(ip)
            else:
                ip = input("Enter IP address to block: ")
                return fw.block_ip(ip)
        # List firewall rules
        elif "list rules" in command or "show rules" in command:
            return fw.list_rules()
        # Remove firewall rule
        elif "remove rule" in command or "delete rule" in command:
            # First show the list of rules
            print(fw.list_rules())
            rule_name = input("Enter the name of the rule to remove: ")
            return fw.remove_rule(rule_name)
        # Generic firewall command - show help
        else:
            return """Firewall Commands:
- 'firewall status' - Show firewall status
- 'firewall enable' - Turn on firewall
- 'firewall disable' - Turn off firewall
- 'firewall add rule for [program]' - Create allow rule for a program
- 'firewall block rule for [program]' - Create block rule for a program
- 'firewall block ip [ip_address]' - Block an IP address
- 'firewall list rules' - Show all custom rules
- 'firewall remove rule' - Delete a firewall rule"""
    
    # Open a specific file
    elif "open file" in command:
        file_name = command.replace("open file", "").strip()
        path, item_type = find_file_or_folder(file_name)
        
        if path and item_type == "file":
            try:
                os.startfile(path)
                return f"Opening file: {os.path.basename(path)}"
            except Exception as e:
                return f"Error opening file: {e}"
        else:
            return f"File '{file_name}' not found. Please check the file name."

    # Open a specific application or folder
    elif "open" in command:
        target_name = command.replace("open", "").strip().lower()
        
        # Get dictionary of installed applications
        installed_apps = get_installed_apps()
        
        # Try to find the app in our dictionary
        if target_name in installed_apps:
            app_path = installed_apps[target_name]
            try:
                # If it's a .lnk file, use os.startfile to handle it
                if app_path.endswith(".lnk"):
                    os.startfile(app_path)
                else:
                    subprocess.Popen(app_path)
                return f"Opening {target_name}."
            except Exception as e:
                return f"Error opening {target_name}: {e}"
        
        # Check if it's a folder or file
        path, item_type = find_file_or_folder(target_name)
        
        if path:
            try:
                os.startfile(path)
                return f"Opening {item_type}: {os.path.basename(path)}"
            except Exception as e:
                return f"Error opening {item_type}: {e}"
        
        # Try other methods if app not found
        try:
            # Try to open with just the app name (assuming it's in system PATH)
            subprocess.Popen(target_name)
            return f"Opening {target_name}."
        except FileNotFoundError:
            # Try with .exe extension
            try:
                subprocess.Popen(target_name + ".exe")
                return f"Opening {target_name}."
            except FileNotFoundError:
                # Ask the user for the path
                print(f"'{target_name}' not found automatically.")
                full_path = input(f"Please provide the full path to {target_name} (or press Enter to skip): ")
                
                if full_path:
                    try:
                        # Check if it's a directory or file
                        if os.path.isdir(full_path):
                            os.startfile(full_path)
                            return f"Opening folder: {os.path.basename(full_path)}"
                        elif os.path.isfile(full_path):
                            os.startfile(full_path)
                            return f"Opening file: {os.path.basename(full_path)}"
                        else:
                            # Assume it's an executable
                            subprocess.Popen(full_path)
                            return f"Opening {target_name} from {full_path}."
                    except Exception as e:
                        return f"Error: Could not open {target_name}. {e}"
                else:
                    return f"Could not find '{target_name}'."

    # Close a specific application
    elif "close" in command:
        app_name = command.replace("close", "").strip().lower()
        
        # Check if the app name ends with .exe
        if not app_name.endswith(".exe"):
            app_name = app_name + ".exe"
        
        # Try to find the process
        found = False
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Check if the process name contains the app name
                if app_name.lower() in proc.info['name'].lower():
                    proc.terminate()
                    found = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if found:
            return f"Closed {app_name}."
        else:
            return f"Couldn't find {app_name} running."

    else:
        return "Command not recognized."

def run_initial_threat_scan():
    """Run an initial threat scan in the background and notify if threats are found."""
    print("Performing initial security scan...")
    results = td.quick_scan()
    
    if results["status"] == "threats_detected":
        count = len(td.threats_found)
        print(f"\n⚠️ SECURITY ALERT: {count} potential threat{'s' if count > 1 else ''} detected!")
        print("Type 'scan threats' for details and options.")
        return True
    else:
        print("Initial security scan complete. No immediate threats detected.")
        return False

def main():
    # Run initial threat scan as the application starts
    threats_detected = run_initial_threat_scan()
    
    # Initialize voice assistant
    speak("Hello! I am your assistant. You can either speak or type a command.")
    if threats_detected:
        speak(f"Warning! Potential security threats have been detected. Type 'scan threats' for details.")
    
    print("\nCommands you can use:")
    print("- 'open [app name]' to open an application")
    print("- 'open file [filename]' to open a file")
    print("- 'close [app name]' to close an application")
    print("- 'scan ports' or 'port scan' to run the port scanner")
    print("- 'scan threats' or 'detect threats' to run the threat detector")
    print("- 'firewall status' to check Windows Firewall status")
    print("- 'firewall enable/disable' to turn firewall on/off")
    print("- 'firewall add rule for [program]' to add a firewall rule")
    print("- 'firewall block ip [IP address]' to block an IP")
    print("- 'firewall list rules' to show all custom firewall rules")
    print("- Any other query will be sent to Gemini AI")
    print("- 'exit' to quit")
    
    while True:
        print("\nSay 'exit' to quit.")
        print("Type 'voice' for voice command or 'text' to enter a command manually.")
        
        mode = input("Select mode (voice/text): ").strip().lower()
        
        if mode == "voice":
            # Get command via voice
            command = listen()
            print(f"You said: {command}")
        elif mode == "text":
            # Get command via text
            command = input("Enter your command: ").strip().lower()
            print(f"You typed: {command}")
        else:
            print("Invalid mode. Please type 'voice' or 'text'.")
            continue
        
        if "exit" in command:
            speak("Goodbye! Feel free to reach out again if you have any other questions or anything else. Have a great day!")
            break

        if "open" in command or "close" in command or "file" in command or "scan" in command or "firewall" in command or "detect" in command:
            response = execute_command(command)
        else:
            response = ai_response(command)

        print(f"Assistant: {response}")
        speak(response)

if __name__ == "__main__":
    main()