import tkinter as tk
import psutil
import ctypes
import time
import ipaddress
import random
import winreg  # Fix missing import

# List of suspicious IPs (for simplicity, you can extend this or query a service)
SUSPICIOUS_IPS = ["1.2.3.4", "5.6.7.8"]  # Example blacklisted IPs

# Global variables to store the active IP and network traffic data
active_ip = "Active IP: Hidden"
prev_bytes_sent = 0
prev_bytes_recv = 0
compromise_box = None  # For the Security Compromised box

# Function to check if an IP is suspicious
def is_suspicious(ip):
    return ip in SUSPICIOUS_IPS

# Function to check firewall status (on Windows)
def check_firewall():
    try:
        return "Enabled"  # Simplified for now
    except:
        return "Unknown"

# Function to check if the program is running as administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Keep track of known PIDs to detect new processes
known_pids = set()

def check_new_processes():
    global known_pids
    new_processes = []
    current_pids = set([p.pid for p in psutil.process_iter()])
    new_pids = current_pids - known_pids
    for pid in new_pids:
        try:
            proc = psutil.Process(pid)
            new_processes.append(f"New process: {proc.name()} (PID: {pid})")
        except psutil.NoSuchProcess:
            pass
    known_pids = current_pids
    return new_processes

def monitor_admin_tasks():
    admin_tasks = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            if proc.info['username'] and proc.info['username'].endswith("Administrator"):
                admin_tasks.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return admin_tasks

def read_registry_key(path, subkey):
    try:
        key = winreg.OpenKey(path, subkey)
        value, _ = winreg.QueryValueEx(key, "")
        winreg.CloseKey(key)
        return value
    except Exception as e:
        return str(e)

# Function to log suspicious activity
def log_event(event_message):
    with open("security_log.txt", "a") as log_file:
        log_file.write(f"{time.ctime()}: {event_message}\n")

# Function to safely exit the widget and break the update loop
def on_closing():
    print("Widget closing")
    if compromise_box is not None:
        compromise_box.destroy()  # Close compromise box if it's open
    widget.quit()  # Stop the Tkinter loop

# Function to check if an IP address is external (not local or private)
def is_external(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback)
    except ValueError:
        return False

# Function to check for simulated security threat (for example, a keylogger or RAT)
SUSPICIOUS_KEYLOGGER_PROCESSES = [
    "keylogger", "logkeys", "kl.exe", "klog.exe", "spylogger",
    "hook", "hookprocess", "sniffer", "keyboardhook"
]

def check_for_threat():
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            process_name = proc.info['name'].lower()
            process_cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
            process_exe = proc.info['exe'].lower() if proc.info['exe'] else ''

            if any(keyword in process_name for keyword in SUSPICIOUS_KEYLOGGER_PROCESSES) or \
               any(keyword in process_cmdline for keyword in SUSPICIOUS_KEYLOGGER_PROCESSES) or \
               any(keyword in process_exe for keyword in SUSPICIOUS_KEYLOGGER_PROCESSES):
                return f"Detected Keylogger: {proc.info['exe']}"

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return None 

# Function to show the Security Compromised box
def show_compromise_box(file_path):
    global compromise_box
    if compromise_box is None:
        compromise_box = tk.Toplevel(widget)
        compromise_box.geometry("600x100")
        compromise_box.configure(bg="black")
        compromise_box.overrideredirect(True)
        compromise_box.attributes("-topmost", True)
        compromise_box.attributes("-alpha", 0.6)

        screen_width = widget.winfo_screenwidth()
        screen_height = widget.winfo_screenheight()
        x = (screen_width // 2) - 450
        y = (screen_height // 2) - 75
        compromise_box.geometry(f"800x100+{x}+{y}")

        compromise_box.bind("<Button-1>", start_drag_compromise)
        compromise_box.bind("<B1-Motion>", on_drag_compromise)

        label = tk.Label(compromise_box, text="Security Compromised", font=("Helvetica", 16, "bold"), bg="black", fg="red")
        label.pack(pady=5)

        file_label = tk.Label(compromise_box, text=f"{file_path}", font=("Helvetica", 12, "bold"), bg="black", fg="red")
        file_label.pack(pady=5)

def start_drag_compromise(event):
    compromise_box.x = event.x
    compromise_box.y = event.y

def on_drag_compromise(event):
    x = compromise_box.winfo_x() + event.x - compromise_box.x
    y = compromise_box.winfo_y() + event.y - compromise_box.y
    compromise_box.geometry(f"+{x}+{y}")

def hide_compromise_box():
    global compromise_box
    if compromise_box is not None:
        compromise_box.destroy()
        compromise_box = None

def update_widget():
    global active_ip, prev_bytes_sent, prev_bytes_recv

    try:
        connections = psutil.net_connections()

        active_connections = []
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr and is_external(conn.raddr.ip):
                active_connections.append(conn)
                active_ip = conn.raddr.ip
                if is_suspicious(conn.raddr.ip):
                    log_event(f"Suspicious connection detected to {conn.raddr.ip}")
        
        if not active_connections:
            active_ip = "No external connection"

        connection_count = len(active_connections)
        
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()

        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent
        bytes_recv = net_io.bytes_recv

        upload_speed = (bytes_sent - prev_bytes_sent) / 1024  # Convert to KB/s
        download_speed = (bytes_recv - prev_bytes_recv) / 1024  # Convert to KB/s

        prev_bytes_sent = bytes_sent
        prev_bytes_recv = bytes_recv

        cpu_label.config(text=f"CPU Usage: {cpu_usage}%")
        connection_label.config(text=f"Total P2P Connections: {connection_count}")
        memory_label.config(text=f"Memory Usage: {memory_info.percent}%")
        upload_label.config(text=f"Upload Speed: {upload_speed:.2f} KB/s")
        download_label.config(text=f"Download Speed: {download_speed:.2f} KB/s")

        firewall_status = check_firewall()
        firewall_label.config(text=f"Firewall: {firewall_status}")
        
        file_path = check_for_threat()
        if file_path:
            show_compromise_box(file_path)
        else:
            hide_compromise_box()

        new_processes = check_new_processes()
        if new_processes:
            new_processes_label.config(text="\n".join(new_processes))
        else:
            new_processes_label.config(text="New Processes: None")

        if is_admin():
            admin_tasks = monitor_admin_tasks()
            if admin_tasks:
                admin_tasks_label.config(text="\n".join(admin_tasks))
            else:
                admin_tasks_label.config(text="Admin Tasks: None")
        else:
            admin_tasks_label.config(text="Run as Administrator for admin tasks.")

        registry_value = read_registry_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        registry_label.config(text=f"Registry Change: {registry_value}")
        
        widget.after(1000, update_widget)

    except KeyboardInterrupt:
        on_closing()

def reveal_ip(event):
    network_status_label.config(text=f"Active IP: {active_ip}")

def hide_ip(event):
    network_status_label.config(text="Active IP: Hidden")

def start_drag(event):
    widget.x = event.x
    widget.y = event.y

def on_drag(event):
    x = widget.winfo_x() + event.x - widget.x
    y = widget.winfo_y() + event.y - widget.y
    widget.geometry(f"+{x}+{y}")

widget = tk.Tk()
widget.geometry("220x265")

user32 = ctypes.windll.user32
screen_width = user32.GetSystemMetrics(0)
screen_height = user32.GetSystemMetrics(1)
widget.geometry(f"+{screen_width - 200}+{screen_height - 190}")

widget.configure(bg="black")
widget.attributes("-alpha", 0.20)
widget.overrideredirect(True)
widget.attributes("-topmost", False)

network_status_label = tk.Label(widget, text="Active IP: Hidden", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
network_status_label.pack(fill="both", pady=2)
network_status_label.bind("<Enter>", reveal_ip)
network_status_label.bind("<Leave>", hide_ip)

cpu_label = tk.Label(widget, text="CPU Usage: 0%", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
cpu_label.pack(fill="both", pady=2)

memory_label = tk.Label(widget, text="Memory Usage: 0%", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
memory_label.pack(fill="both", pady=2)

new_processes_label = tk.Label(widget, text="New Processes: None", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
new_processes_label.pack(fill="both", pady=2)

admin_tasks_label = tk.Label(widget, text="Admin Tasks: None", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
admin_tasks_label.pack(fill="both", pady=2)

registry_label = tk.Label(widget, text="Registry Change: None", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
registry_label.pack(fill="both", pady=2)

connection_label = tk.Label(widget, text="Total P2P Connections: 0", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
connection_label.pack(fill="both", pady=2)

upload_label = tk.Label(widget, text="Upload Speed: 0 KB/s", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
upload_label.pack(fill="both", pady=2)

download_label = tk.Label(widget, text="Download Speed: 0 KB/s", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
download_label.pack(fill="both", pady=2)

firewall_label = tk.Label(widget, text="Firewall: Unknown", font=("Helvetica", 10), bg="black", fg="white", anchor="w")
firewall_label.pack(fill="both", pady=2)

widget.bind("<Button-1>", start_drag)
widget.bind("<B1-Motion>", on_drag)

widget.protocol("WM_DELETE_WINDOW", on_closing)

update_widget()
widget.mainloop()
