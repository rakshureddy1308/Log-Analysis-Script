import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for brute force detection
FAILED_LOGIN_THRESHOLD = 10

# File paths
log_file = "sample.log"
output_csv = "log_analysis_results.csv"

# Regular expressions for parsing log
log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).+\[(?P<timestamp>.+?)\] "(?P<method>\w+) (?P<endpoint>/\S*) HTTP/\d\.\d" (?P<status>\d+) (?P<size>\d+)(?: "(?P<message>.+)")?')

# Data structures to store results
ip_requests = Counter()
endpoint_requests = Counter()
failed_logins = defaultdict(int)

# Parse the log file
with open(log_file, "r") as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            data = match.groupdict()
            ip = data['ip']
            endpoint = data['endpoint']
            status = int(data['status'])
            message = data.get('message', '')

            # Count requests per IP and endpoint
            ip_requests[ip] += 1
            endpoint_requests[endpoint] += 1

            # Identify failed login attempts
            if endpoint == "/login" and status == 401 and "Invalid credentials" in message:
                failed_logins[ip] += 1

# Sort requests per IP in descending order
sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

# Find the most accessed endpoint
most_accessed_endpoint, access_count = endpoint_requests.most_common(1)[0]

# Identify suspicious activity
suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

# Prepare data for CSV
requests_per_ip_data = [{"IP Address": ip, "Request Count": count} for ip, count in sorted_ip_requests]
most_accessed_endpoint_data = [{"Endpoint": most_accessed_endpoint, "Access Count": access_count}]
suspicious_activity_data = [{"IP Address": ip, "Failed Login Count": count} for ip, count in suspicious_ips.items()]

# Write to CSV
with open(output_csv, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    # Write Requests per IP
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for row in requests_per_ip_data:
        writer.writerow(row.values())

    # Write Most Accessed Endpoint
    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    for row in most_accessed_endpoint_data:
        writer.writerow(row.values())

    # Write Suspicious Activity
    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    for row in suspicious_activity_data:
        writer.writerow(row.values())

# Display results in terminal
print("\nRequests per IP (Descending Order):")
for row in requests_per_ip_data:
    print(f"{row['IP Address']}: {row['Request Count']} requests")

print("\nMost Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {access_count} times)")

print("\nSuspicious Activity (Failed Login Attempts Exceeding Threshold):")
if suspicious_activity_data:
    print(f"{'IP Address':<20} {'Failed Login Count':<20}")
    for row in suspicious_activity_data:
        print(f"{row['IP Address']:<20} {row['Failed Login Count']:<20}")
else:
    print("No suspicious activity detected.")

print(f"\nResults saved to {output_csv}")
