import re
import csv
from collections import Counter, defaultdict

# File paths
log_file = "sample.log"
output_csv = "log_analysis_results.csv"

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Parse log file
def parse_log_file(file_path):
    with open(file_path, "r") as file:
        log_lines = file.readlines()
    return log_lines

# Extract IPs and endpoints
def extract_data(log_lines):
    ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
    endpoint_pattern = r"\"(?:GET|POST) (/[^\s]*)"
    status_code_pattern = r"\" (\d{3})"
    failed_message_pattern = r"Invalid credentials"

    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_attempts = defaultdict(int)

    for line in log_lines:
        # Extract IP address
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            ip = ip_match.group(1)
            ip_counter[ip] += 1

        # Extract endpoint
        endpoint_match = re.search(endpoint_pattern, line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counter[endpoint] += 1

        # Detect failed logins
        status_match = re.search(status_code_pattern, line)
        if status_match and status_match.group(1) == "401":
            failed_attempts[ip] += 1
        elif failed_message_pattern in line:
            failed_attempts[ip] += 1

    return ip_counter, endpoint_counter, failed_attempts

# Write results to CSV
# Write results to CSV
def write_csv(ip_data, endpoint_data, suspicious_data):
    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        
        # Section: Requests Per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_data.most_common():
            writer.writerow([ip, count])
        
        writer.writerow([])  # Empty line for separation

        # Section: Most Accessed Endpoint
        writer.writerow(["Most Frequently Accessed Endpoint:"])
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_data.most_common(1):
            writer.writerow([endpoint, count])
        
        writer.writerow([])  # Empty line for separation

        # Section: Suspicious Activity
        writer.writerow(["Suspicious Activity Detected:"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_data.items():
            writer.writerow([ip, count])

# Display results
def display_results(ip_data, endpoint_data, suspicious_data):
    print("IP Address           Request Count")
    for ip, count in ip_data.most_common():
        print(f"{ip:<20}{count}")

    most_accessed = endpoint_data.most_common(1)[0]
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_data.items():
        print(f"{ip:<20}{count}")

# Main function
def main():
    log_lines = parse_log_file(log_file)
    ip_counter, endpoint_counter, failed_attempts = extract_data(log_lines)

    # Filter suspicious activity based on threshold
    suspicious_data = {ip: count for ip, count in failed_attempts.items()}

    # Display results
    display_results(ip_counter, endpoint_counter, suspicious_data)

    # Save results to CSV
    write_csv(ip_counter, endpoint_counter, suspicious_data)

if __name__ == "__main__":
    main()
