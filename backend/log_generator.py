import time
import random
import requests

API_URL = "http://127.0.0.1:5000/logs"

# Sample data
IPS = [
    "192.168.1.5", "10.0.0.12", "172.16.0.22", "8.8.8.8",
    "192.168.1.100", # Suspicious IP
    "10.0.0.99"      # Suspicious IP
]
ATTACKER_IP = "203.0.113.45" # Used for brute force simulation

EVENT_TYPES = ["successful_login", "failed_login", "system_start", "config_change", "data_export"]
USERS = ["admin", "john.doe", "jane.smith", "guest", "service_account"]

def generate_normal_log():
    ip = random.choice(IPS)
    event = random.choice(EVENT_TYPES)
    user = random.choice(USERS)
    
    if event == "failed_login":
        desc = f"Failed login attempt for user '{user}'"
    elif event == "successful_login":
        desc = f"User '{user}' logged in successfully"
    else:
        desc = f"System event '{event}' triggered by user '{user}'"
        
    return {
        "ip_address": ip,
        "event_type": event,
        "description": desc
    }

def simulate_brute_force():
    print(f"--- Simulating Brute Force Attack from {ATTACKER_IP} ---")
    user = "admin"
    for _ in range(6): # Triggers the threshold of 5
        log_data = {
            "ip_address": ATTACKER_IP,
            "event_type": "failed_login",
            "description": f"Failed login attempt for user '{user}'"
        }
        try:
            requests.post(API_URL, json=log_data)
            print(f"Sent failed login from {ATTACKER_IP}")
        except Exception as e:
            print(f"Error sending log: {e}")
        time.sleep(0.5)

def simulate_traffic_spike():
    print("--- Simulating Traffic Spike ---")
    for _ in range(55): # Triggers threshold of 50
        log_data = generate_normal_log()
        try:
            requests.post(API_URL, json=log_data)
        except Exception:
            pass
    print("Traffic spike generation complete.")

if __name__ == "__main__":
    print("Starting SOC Log Generator...")
    print("Waiting 3 seconds for backend to be ready...")
    time.sleep(3)
    
    counter = 0
    while True:
        # 1. Normal traffic
        log_data = generate_normal_log()
        try:
            response = requests.post(API_URL, json=log_data)
            print(f"Sent normal log: {log_data['event_type']} from {log_data['ip_address']}")
        except requests.exceptions.ConnectionError:
            print("Failed to connect to API. Is the server running?")
        
        counter += 1
        
        # 2. Simulate brute force every ~30 normal logs
        if counter % 30 == 0:
            simulate_brute_force()
            
        # 3. Simulate traffic spike every ~100 normal logs
        if counter % 100 == 0:
            simulate_traffic_spike()
            
        time.sleep(random.uniform(0.5, 2.5))
