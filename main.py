import re
import argparse
from datetime import datetime
from typing import Counter


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'                                                           # client IP
    r'\S+\s+\S+\s+'                                                              # ident, authuser (usually "-")
    r'\[(?P<time>[^\]]+)\]\s+'                                                   # [01/Jun/2026:09:14:22 +0000]
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'             # "GET /path HTTP/1.1"
    r'(?P<status>\d{3})\s+'                                                      # status code
    r'(?P<size>\d+|-)\s+'                                                        # response size (bytes) or "-"
    r'"(?P<referer>[^"]*)"\s+'                                                   # referer
    r'"(?P<user_agent>[^"]*)"'                                                   # user-agent
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class LogStats:
    def __init__(self):
        self.total_lines = 0
        self.valid_requests = 0
        self.corrupted_lines = 0

        self.unique_ips = set()
        self.endpoint_counter = Counter()
        self.hourly_counter = Counter()      
        self.status_counter = Counter()
        self.error_count = 0     



def process_line(line):
    match = LOG_PATTERN.match(line)
    if not match:
        # print("Line did not match log pattern:", line.strip())
        return None
    data = match.groupdict()

    try:
        if not (100 <= int(data["status"]) <= 599):
            # print("Invalid status code:", data["status"])
            return None
    except (ValueError, TypeError):
        # print("Error occurred while processing status code:", data["status"])
        return None
    
    try:
        datetime.strptime(data["time"], TIME_FORMAT)
    except ValueError:
        # print("Error occurred while processing timestamp:", data["time"])
        return None
    
    return data


def process_log_file(log_file_path, output_file_path):

    stats = LogStats()

    with open(log_file_path, "r", encoding="utf-8") as f:
        for line in f:
            stats.total_lines += 1
            data = process_line(line)

            if data is None:
                stats.corrupted_lines += 1
                continue

            stats.valid_requests += 1
            stats.unique_ips.add(data["ip"])
            stats.endpoint_counter[data["path"]] += 1
            stats.status_counter[data["status"]] += 1

            timestamp = datetime.strptime(data["time"], TIME_FORMAT)
            hour_str = timestamp.strftime("%Y-%m-%d %H:00:00")
            stats.hourly_counter[hour_str] += 1


            if data["status"].startswith("4") or data["status"].startswith("5"):
                stats.error_count += 1

    return stats


def print_report(stats, top_n=None):
    print("=" * 70)
    print("LOG REPORT")
    print("=" * 70)

    print("\n-- Parsing Summary --")
    print(f"Total lines read       : {stats.total_lines:,}")
    print(f"Valid requests parsed  : {stats.valid_requests:,}")
    print(f"Corrupted/skipped lines: {stats.corrupted_lines:,}")

    print("\n-- Base Report --")
    print(f"Total requests   : {stats.valid_requests:,}")
    print(f"Unique IPs       : {len(stats.unique_ips):,}")
    print(f"Error rate (4xx/5xx): {(stats.error_count / stats.valid_requests * 100):.2f}%")


    print("\n-- Status Code Breakdown --")
    for status in sorted(stats.status_counter):
        count = stats.status_counter[status]
        pct = (count / stats.valid_requests * 100) if stats.valid_requests else 0
        print(f"  {status}: {count:>8,}  ({pct:5.2f}%)")



    print("\n" + "=" * 70)


if __name__ == "__main__":  
    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument("--output", type=str, default="result.txt")
    parser.add_argument("--top", type=int)
    args = parser.parse_args()

    log_file_path = args.log_file
    output_file_path = args.output
    top_lines = args.top

    if top_lines is None:
        stats = process_log_file(log_file_path, output_file_path)

    print_report(stats, top_n=top_lines)
