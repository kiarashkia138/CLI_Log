# Access Log Analyzer

A small CLI tool that reads a web server access log (Combined Log Format) and prints out a quick report: traffic totals, error rates, busiest endpoints, hourly traffic, and suspicious login attempts.


## Usage

```bash
python main.py access.log
python main.py access.log.gz
```

Both plain `.log` files and gzip-compressed `.gz` files work — the tool picks the right one based on the extension.

### Options

| Flag | Default | Description |
|---|---|---|
| `--top N` | 10 | How many top endpoints to show |
| `--login-threshold N` | 10 | Minimum number of failed (401) login attempts before an IP is flagged as suspicious |

Example:

```bash
python log_analyzer.py access.log --top 10 --login-threshold 10
```

## What it reports

- **Parsing summary** — total lines read, how many parsed successfully, how many were corrupted/skipped
- **Base stats** — total requests, unique IPs, error rate (% of 4xx/5xx responses)
- **Top endpoints** — busiest paths by request count
- **Status code breakdown** — count and % for each status code seen
- **Hourly traffic distribution** — a simple text histogram showing peaks and drops by hour
- **Suspicious login activity** — IPs with repeated 401 responses on login-related paths, a possible sign of a brute-force attempt
- **Processing time** — how long the run took, printed at the end

## Expected log format

Combined Log Format, one request per line:

```
203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0 ..."
```

Any line that doesn't match this format — truncated, garbled, missing fields, bad timestamp, bad status code — is counted as corrupted and skipped. The tool never crashes on bad input; it just tells you how many lines it couldn't parse.



## Implementation details

**Parsing** — one regex (`LOG_PATTERN`) matches an entire log line at once, with a named group per field (`ip`, `time`, `method`, `path`, `protocol`, `status`, `size`, `referer`, `user_agent`). Quoted fields (request line, referer, user-agent) are matched as `"[^"]*"` so they can contain spaces without breaking the parse. If the regex doesn't match, or the status code isn't a valid 3-digit number in 100–599, or the timestamp fails `datetime.strptime()`, the line is counted as corrupted and skipped.

**Streaming** — the file is read with `for line in f:` inside `process_log_file()`, so only one line is ever held in memory at a time. The running totals are kept in a handful of `collections.Counter` objects and a `set` for unique IPs.

**Compressed files** — `open_log_file()` checks whether the path ends in `.gz` and opens it with `gzip.open(path, "rt", ...)` instead of the normal `open()`. Everything downstream reads it the same way either way, since both return a text-mode file object.

**Suspicious login detection** — every 401 response on a path containing the word `login` gets tallied per `(ip, path)` in a `Counter`. After the file is processed, `suspicious_login_ips()` sums those counts per IP and returns any IP at or above `--login-threshold` failed attempts, sorted by count.

**Hourly histogram** — `render_histogram_bar()` turns each hour's request count into a row of `#` characters, scaled against the busiest hour (`max_count`). The busiest hour always gets the full 50-character bar; every other hour is `count / max_count * 50`, rounded down. This gives a quick visual read of traffic peaks and drops without having to compare raw numbers by eye, e.g.:

```
2026-06-01 07:00:00   50,844  #################################################
2026-06-01 08:00:00   50,912  #################################################
2026-06-01 09:00:00   36,953  ####################################
```


## A problem I ran into 

Some fields in the log, like the user-agent contain spaces inside them:
```
    "Mozilla/5.0 (X11; Linux x86_64)"
```
My first approach was splitting each line on whitespace to pull out the fields. That broke as soon as it hit a user-agent with spaces in it

### Fix
instead of splitting the fields, I built one regex (LOG_PATTERN) that validates the entire line's structure in a single match. If a line doesn't match — wrong number of fields, malformed quotes, etc — match just comes back None and I skip it.
