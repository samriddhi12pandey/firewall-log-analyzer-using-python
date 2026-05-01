# log_parser.py
# Handles all parsing logic for firewall log files
# Kept separate from app.py to follow Single Responsibility Principle

import re
from collections import Counter

# Keywords that indicate a blocked/denied request
BLOCK_KEYWORDS = ["BLOCK", "DENY", "DENIED", "BLOCKED", "DROP", "DROPPED"]

def parse_logs(file_content: str) -> dict:
    """
    Parse raw firewall log content and return analysis results.

    Args:
        file_content (str): Raw text content of the uploaded log file.

    Returns:
        dict: Contains total_logs, blocked_requests, and top_5_ips.
    """

    # Split file into individual log lines, skip empty lines
    lines = [line.strip() for line in file_content.splitlines() if line.strip()]

    total_logs = len(lines)
    blocked_count = 0
    ip_list = []

    # Regex pattern to match an IPv4 address anywhere in the line
    ip_pattern = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

    for line in lines:
        # --- Check if this line represents a blocked request ---
        # Convert line to uppercase for case-insensitive matching
        line_upper = line.upper()
        if any(keyword in line_upper for keyword in BLOCK_KEYWORDS):
            blocked_count += 1

        # --- Extract IP addresses from the line ---
        ips_in_line = ip_pattern.findall(line)
        # Add the first IP found per line (source IP is usually first)
        if ips_in_line:
            ip_list.append(ips_in_line[0])

    # --- Calculate top 5 most frequent IPs ---
    ip_counter = Counter(ip_list)
    top_5_ips = [
        {"ip": ip, "count": count}
        for ip, count in ip_counter.most_common(5)
    ]

    return {
        "total_logs": total_logs,
        "blocked": blocked_count,       # renamed from blocked_requests
        "top_ips": top_5_ips            # renamed from top_5_ips
    }
