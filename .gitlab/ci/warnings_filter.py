#!/usr/bin/python3

import sys
import json
import linecache

if __name__ == "__main__":
    json_string = sys.stdin.read()
    if json_string in [None, ""]:
        sys.exit(0)

    parsed = json.loads(json_string)
    #print(json.dumps(parsed, indent=4, sort_keys=True))

    r = 0

    for o in parsed:
        kind = o["kind"]

        start = o["locations"][0]["caret"]
        l = linecache.getline(start["file"], int(start["line"]))

        ignored = "json_object_object_foreach" in l

        print(f"{o['kind']} {'ignored' if ignored else 'FOUND'} in {start['file']}:{start['line']}:{start['column']} {o['message']}")
        print(f"line contains:\n\t{l}", end="")

        if not ignored:
            r = 1

    sys.exit(r)
