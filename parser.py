#!/usr/bin/env python3
import argparse
import re
import sys
import json
from collections import defaultdict
from datetime import datetime

LOG_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"$'
)

TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"  # example: 04/Oct/2025:20:01:23 +0000


def parse_line(line: str):
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()

    d['status'] = int(d['status'])
    d['size'] = int(d['size']) if d['size'] != '-' else None

    # try to parse time
    try:
        d['time'] = datetime.strptime(d['time'], TIME_FMT)
    except Exception:
        # leave raw string if parsing fails
        pass

    return d


def top_ips(parsed):
    top_ips = defaultdict(int)

    for rec in parsed:
        top_ips[rec["ip"]]+=1

    for ip, count in sorted(top_ips.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count}")


def parse_stream(f):
    for lineno, line in enumerate(f, 1):
        parsed = parse_line(line)
        if parsed:
            yield parsed


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--top_ips", action="store_true", help="count top ip addrs")
    p.add_argument("--output_jsonl", action="store_true", help="output parsed data as jsonl")
    args = p.parse_args()

    src = sys.stdin

    if args.top_ips:
        top_ips(parse_stream(src))

    if args.output_jsonl:
        for rec in parse_stream(src):
            print(json.dumps(rec, default=str, ensure_ascii=False))
