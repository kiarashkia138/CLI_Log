import re
import gzip
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

        self.auth_keywords = ["login"]
        self.auth_401_by_ip_path = Counter()

    def _is_auth_path(self, path):
        p = path.lower()
        return any(kw in p for kw in self.auth_keywords)

    def suspicious_login_ips(self, threshold=10, top_n=10):
        """
        Aggregate 401-on-auth-path counts per IP (across all matching paths)
        and return those at/above `threshold`, sorted descending, along with
        a per-path breakdown for each offending IP.
        """
        totals = Counter()
        breakdown = {}  # ip -> Counter(path -> count)
        for (ip, path), count in self.auth_401_by_ip_path.items():
            totals[ip] += count
            breakdown.setdefault(ip, Counter())[path] += count

        offenders = [
            (ip, total, breakdown[ip])
            for ip, total in totals.items()
            if total >= threshold
        ]
        offenders.sort(key=lambda x: x[1], reverse=True)
        return offenders[:top_n] 


def open_log_file(filepath):
    if filepath.endswith(".gz"):
        return gzip.open(filepath, "rt", encoding="utf-8", errors="replace")
    
    return open(filepath, "r", encoding="utf-8", errors="replace")


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


def process_log_file(log_file_path):

    stats = LogStats()

    with open_log_file(log_file_path) as f:
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

            if data["status"] == 401 and stats._is_auth_path(data["path"]):
                stats.auth_401_by_ip_path[(data["ip"], data["path"])] += 1

    return stats


def render_histogram_bar(count, max_count, width=50):
    if max_count == 0:
        return ""
    filled = int((count / max_count) * width)
    return "#" * filled


def print_report(stats, top_n=10, login_thr=10):
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

    print(f"\nTop {top_n} endpoints by traffic:")
    top_endpoints = stats.endpoint_counter.most_common(top_n)
    if not top_endpoints:
        print("  (no data)")
    else:
        max_len = max(len(path) for path, _ in top_endpoints)
        for path, count in top_endpoints:
            print(f"  {path:<{max_len}}  {count:>8,} requests")


    print("\n-- Status Code Breakdown --")
    for status in sorted(stats.status_counter):
        count = stats.status_counter[status]
        pct = (count / stats.valid_requests * 100) if stats.valid_requests else 0
        print(f"  {status}: {count:>8,}  ({pct:5.2f}%)")


    print("\n-- Hourly Traffic Distribution --")
    hourly = sorted(stats.hourly_counter.items())
    if not hourly:
        print("  (no data)")
    else:
        max_count = max(c for _, c in hourly)
        for hour_bucket, count in hourly:
            bar = render_histogram_bar(count, max_count)
            print(f"  {hour_bucket}  {count:>7,}  {bar}")


    print("\n-- Suspicious Login Activity --")
    print(f"(IPs with >= {login_thr} failed (401) attempts on auth-like "
          f"endpoints: {', '.join(stats.auth_keywords)})")
    offenders = stats.suspicious_login_ips(threshold=login_thr)
    if not offenders:
        print("  No suspicious login activity detected.")
    else:
        for ip, total, breakdown in offenders:
            print(f"  {ip:<20} {total:>6,} failed logins")
            for path, count in breakdown.most_common():
                print(f"      -> {path:<30} {count:>6,}")


    print("\n" + "=" * 70)



if __name__ == "__main__":  
    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--login-threshold", type=int, default=10)
    args = parser.parse_args()

    log_file_path = args.log_file
    top_lines = args.top
    login_thr = args.login_threshold


    if not log_file_path.endswith((".log", ".gz")):
        raise argparse.ArgumentTypeError("File must end with '.log' or '.gz'")


    stats = process_log_file(log_file_path)
    print_report(stats, top_n=top_lines, login_thr=login_thr)
