import argparse
import re


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


def process_log_file(log_file_path, output_file_path):

    with open(log_file_path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            match = LOG_PATTERN.match(line)
            if not match:
                return None
            data = match.groupdict()
            print(data)



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
        process_log_file(log_file_path, output_file_path)
