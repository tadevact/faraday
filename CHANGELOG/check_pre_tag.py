#!/usr/bin/env python3
from pathlib import Path
import argparse
import os

class FileError(Exception):
    pass

parser = argparse.ArgumentParser()
parser.add_argument('--version', default=None)
args = parser.parse_args()


def main(version_id):
    changelog_folder = Path(__file__).parent
    current_folder = changelog_folder / "current"
    for file in os.listdir(current_folder):
        if file != ".keep":
            raise FileError(f"Unexpected file found: {file}")
    version_folder = changelog_folder / version_id
    valid_files = ["date.md", "community.md", "prof.md", "corp.md"]
    for file in os.listdir(version_folder):
        if file not in valid_files:
            raise FileError(f"Unexpected file found: {file}")


if __name__ == '__main__':
    version = os.environ.get("FARADAY_VERSION", args.version)
    main(version)
