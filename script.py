import csv

# Configurable parameters
FAILED_LOGIN_THRESHOLD = 5
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'

# Parse the log file
def parse_log_file(file_path):
    # Dictionaries to count occurrences
    ip_count = {}
    endpoint_count = {}
    failed_logins = {}

    try:
        with open(file_path, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 9:  # Ensure the log line has enough parts
                    continue  # Skip malformed lines

                ip = parts[0]
                endpoint = parts[6]
                status_code = parts[8]

                # Count requests by IP
                if ip in ip_count:
                    ip_count[ip] += 1
                else:
                    ip_count[ip] = 1

                # Count endpoint accesses
                if endpoint in endpoint_count:
                    endpoint_count[endpoint] += 1
                else:
                    endpoint_count[endpoint] = 1

                # Track failed login attempts (401 status code)
                if status_code == '401':
                    if ip in failed_logins:
                        failed_logins[ip] += 1
                    else:
                        failed_logins[ip] = 1
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
        return {}, {}, {}

    return ip_count, endpoint_count, failed_logins

# Find the most accessed endpoint
def identify_most_accessed_endpoint(endpoint_count):
    if not endpoint_count:
        return None, 0
    most_accessed_endpoint = None
    max_count = 0
    for endpoint, count in endpoint_count.items():
        if count > max_count:
            most_accessed_endpoint = endpoint
            max_count = count
    return most_accessed_endpoint, max_count

# Detect suspicious activity
def detect_suspicious_activity(failed_logins, threshold):
    suspicious_ips = {}
    for ip, count in failed_logins.items():
        if count > threshold:
            suspicious_ips[ip] = count
    return suspicious_ips

# Save results to CSV
def save_results_to_csv(ip_count, most_accessed, suspicious_activity, output_file):
    try:
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write header for IP counts
            writer.writerow(['Requests per IP'])
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in ip_count.items():
                writer.writerow([ip, count])

            # Write header for the most accessed endpoint
            writer.writerow([])
            writer.writerow(['Most Accessed Endpoint'])
            writer.writerow(['Endpoint', 'Access Count'])
            writer.writerow([most_accessed[0], most_accessed[1]])

            # Write suspicious activity section
            writer.writerow([])
            writer.writerow(['Suspicious Activity'])
            writer.writerow(['IP Address', 'Failed Login Count'])
            for ip, count in suspicious_activity.items():
                writer.writerow([ip, count])
    except Exception as e:
        print(f"Error saving results to CSV: {e}")

# Main function
def main():
    # Parse the log file
    ip_count, endpoint_count, failed_logins = parse_log_file(LOG_FILE)

    # Identify most accessed endpoint
    most_accessed = identify_most_accessed_endpoint(endpoint_count)

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD)

    # Print results to the console
    print("\n=== Analysis Results ===")
    print("\nRequests Per IP:")
    for ip, count in ip_count.items():
        print(f"{ip}: {count} requests")

    print("\nMost Accessed Endpoint:")
    if most_accessed[0]:
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("No endpoints accessed.")

    print("\nSuspicious Activity:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip}: {count} failed login attempts")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_results_to_csv(ip_count, most_accessed, suspicious_activity, OUTPUT_CSV)
    print("\nResults saved to", OUTPUT_CSV)

if __name__ == "__main__":
    main()
