import subprocess
import re
import time
import os
import argparse

def main():
    parser = argparse.ArgumentParser(description="Detect suspicious HTTP requests and deny access to IP addresses.")
    parser.add_argument("-p", "--port", type=int, help="Port number to be guarded", required=True)
    parser.add_argument("-t", "--threshold", type=int, help="Number of HTTP requests for consider an IP like suspicious", required=True)
    parser.add_argument("-i", "--interval", type=int, help="Time in seconds between requests to classify as suspicious activity", required=True)
    args = parser.parse_args()

    port = args.port
    threshold = args.threshold
    interval = args.interval
    print(f"Guarding port {port} with threshold {threshold} and interval {interval} seconds")
    ip_counts = {}
    ip_timestamps = {} 

    command = f"sudo tcpdump -l -i any -nn 'tcp port {port}'"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        for line in process.stdout:
            line_str = line.decode().strip()
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line_str)  
            if match:
                src_ip = match.group(0)
                
                if "In" in line_str:
                    current_time = time.time()
                    
                    if src_ip in ip_timestamps:
                        last_timestamp = ip_timestamps[src_ip]
                        time_diff = current_time - last_timestamp
                        if time_diff <= interval:  
                            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                    ip_timestamps[src_ip] = current_time 
                    
                    if ip_counts.get(src_ip, 0) > threshold:
                        print(f"Blocking suspicious IP: {src_ip}")
                        os.system(f"sudo ufw deny from {src_ip} to any port {port}")

    except KeyboardInterrupt:
        process.terminate()

if __name__ == "__main__":
    main()
