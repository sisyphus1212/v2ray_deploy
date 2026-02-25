#!/usr/bin/env python
import os
import runpy
import sys


def main() -> int:
    here = os.path.dirname(os.path.realpath(__file__))
    target = os.path.join(here, "app", "proxy_mgt.py")
    if not os.path.exists(target):
        print(f"error: missing {target}", file=sys.stderr)
        return 2
    runpy.run_path(target, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
