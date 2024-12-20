#Log Analysis System


Key Features
- IP Traffic Analysis: Tracks and summarizes request frequency per IP address
- Endpoint Monitoring: Identifies the most frequently accessed endpoints
- Security Analysis: Detects suspicious activity based on failed login attempts

Technical Implementation
- Built in Python using standard libraries and minimal dependencies
- Implements efficient data processing using Counter collections
- Uses regex pattern matching for accurate log parsing

Suspicious Activity
- This section flags IP addresses with suspicious behavior, such as excessive failed login attempts.
- IP Address: The IP address exhibiting suspicious activity.
- Failed Login Count: The total number of failed login attempts from the IP address.


Sample Output
The system generates three types of analysis:
- Requests Per IP: Shows traffic distribution across different IP addresses
- Popular Endpoints: Identifies most accessed URLs/endpoints
- Security Alerts: Flags IPs with suspicious activity (e.g., multiple failed logins)


	

