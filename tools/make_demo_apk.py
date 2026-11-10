"""Generate an intentionally malformed APK upload fixture for the SENTRA demo.

This is NOT an installable Android app or malware sample. It demonstrates that
SENTRA rejects a corrupt .apk upload gracefully without crashing or leaking
server details.
"""
from pathlib import Path
import argparse


def build_demo_apk():
    return b"SENTRA DEMO - INTENTIONALLY INVALID APK\nThis is not a ZIP or Android package.\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="sentra-malformed-demo.apk")
    args = parser.parse_args()
    path = Path(args.output)
    path.write_bytes(build_demo_apk())
    print(f"Wrote intentionally malformed demo fixture: {path.resolve()}")
    print("Upload this file to demonstrate safe rejection. It is not installable.")


if __name__ == "__main__":
    main()
