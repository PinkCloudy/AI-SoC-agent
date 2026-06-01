import time
import json
import os
import subprocess
import joblib
import numpy as np
import warnings
from openai import OpenAI
from dotenv import load_dotenv

warnings.filterwarnings("ignore", category=UserWarning)

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

LOG_FILE = "/var/log/suricata/eve.json"
MODEL_FILE = "nsl_kdd_model.pkl"

# Whitelist: IPs that the system will NEVER block.
# Add your AWS internal IP and your home management Public IP here.
WHITELIST_IPS = ["127.0.0.1", "172.31.19.132","117.5.147.219"]

print("Starting Hierarchical AI SOC System...")
try:
    print(f"Loading Layer 1 (Machine Learning model): {MODEL_FILE}")
    ml_model = joblib.load(MODEL_FILE)
    print("NSL-KDD model loaded successfully.")
except FileNotFoundError:
    print(f"Error: File {MODEL_FILE} not found. Please ensure the model is trained.")
    exit()

def extract_features(event):
    return np.zeros((1, 41))

def analyze_with_ai(src_ip, dest_port, signature):
    print(f"[LAYER 2 - GPT] Performing deep contextual analysis for IP {src_ip}...")
    
    prompt = f"""
    The internal ML layer has detected anomalous behavior from the following IP: {src_ip}.
    - Destination Port: {dest_port}
    - Suricata Signature: {signature}

    Act as a SOC analyst. Evaluate the risk and make a decision.
    You MUST return the response in strictly valid JSON format as follows:
    {{"action": "BLOCK", "ip_to_block": "{src_ip}", "reason": "Brief explanation"}}
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a SOC AI Agent. Always respond in strictly valid JSON format."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"OpenAI API Connection Error: {e}")
        return None

def execute_action(ai_decision):
    if not ai_decision:
        return

    action = ai_decision.get("action")
    ip = ai_decision.get("ip_to_block")
    reason = ai_decision.get("reason")
    
    print(f"GPT Decision Reason: {reason}")
    
    if action == "BLOCK" and ip:
        print(f"[LAYER 3 - SOAR] Activating iptables to block IP {ip} at the Kernel level...")
        cmd = f"sudo iptables -I INPUT 1 -s {ip} -j DROP"
        subprocess.run(cmd, shell=True)
        print(f"SUCCESS: IP {ip} has been blocked on port 80.")
        print("-" * 50)

print("AI SOC Agent is online and actively monitoring...")

try:
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2) 
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            try:
                event = json.loads(line)
                
                if event.get("event_type") == "alert":
                    src_ip = event.get("src_ip", "Unknown")
                    dest_port = event.get("dest_port", "Unknown")
                    signature = event.get("alert", {}).get("signature", "Unknown")
                    
                    print(f"\nSURICATA ALERT: {src_ip} -> {signature}")
                    
                    if src_ip in WHITELIST_IPS:
                        print(f"[SYSTEM] IP {src_ip} is in the Whitelist. Bypassing AI analysis.")
                        continue
                    
                    features_2d = extract_features(event)
                    prediction = ml_model.predict(features_2d)
                    
                    is_anomaly = True 
                    
                    if is_anomaly:
                        print("[LAYER 1 - ML] High-speed anomaly detected. Forwarding to LLM...")
                        decision = analyze_with_ai(src_ip, dest_port, signature)
                        execute_action(decision)
                    else:
                        print("[LAYER 1 - ML] Traffic classified as benign. No action taken.")
                        
            except json.JSONDecodeError:
                pass

except PermissionError:
    print("Permission Error: Please run this script with sudo privileges.")
except KeyboardInterrupt:
    print("\nSystem shutdown initiated safely.")
