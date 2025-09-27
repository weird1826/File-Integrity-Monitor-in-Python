import os  # To walk through directories and get file paths
import hashlib  # To perform SHA-265 hashing
import json  # To save and load the baseline file
import argparse
import logging
import configparser
import fnmatch
from datetime import datetime

BUFFER_SIZE = 65536  # Read files in 64kb chunks
BASELINE_FILE = "baseline.json"


def setup_logging():
    logger = logging.getLogger('FIM')
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler('fim.log')
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


logger = setup_logging()


def load_config():
    config = configparser.ConfigParser()
    exclusions = {'dirs': [], 'files': []}

    if os.path.exists('config.ini'):
        config.read('config.ini')
        if 'Exclusions' in config:
            exclusions['dirs'] = config['Exclusions'].get(
                'exclude_dirs', '').split(',')
            exclusions['files'] = config['Exclusions'].get(
                'exclude_files', '').split(',')

            exclusions['dirs'] = [p.strip()
                                  for p in exclusions['dirs'] if p.strip()]
            exclusions['files'] = [p.strip()
                                   for p in exclusions['files'] if p.strip()]
            logger.info("Loaded exclusion config: %s", exclusions)

    return exclusions


def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                data = f.read(BUFFER_SIZE)  # Read file in chunks
                if not data:
                    break
                sha256_hash.update(data)
    except IOError:
        return None

    return sha256_hash.hexdigest()


def is_excluded(path, exclusions):
    for pattern in exclusions['dirs']:
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
            return True

    for pattern in exclusions['files']:
        if fnmatch.fnmatch(os.path.basename(path), pattern):
            return True

    return False


def create_basline(directory, exclusions):
    baseline = {}
    print(f"[*] Creating baseline for directory: {directory}")

    for dirpath, dirnames, filenames in os.walk(directory):

        dirnames[:] = [d for d in dirnames if not is_excluded(
            os.path.join(dirpath, d), {'dirs': exclusions['dirs'], 'files': []})]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if is_excluded(filepath, exclusions):
                continue

            file_hash = get_file_hash(filepath)
            if file_hash:
                relative_path = os.path.relpath(filepath, directory)
                baseline[relative_path] = file_hash

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    print(f"[+] Baseline created successfully! {len(baseline)} files scanned.")


def check_integrity(directory, exclusions):
    try:
        with open(BASELINE_FILE, "r") as f:
            baseline = json.load(f)
    except FileNotFoundError:
        print(
            f"[-] Baseline file '{BASELINE_FILE}' not found. Please create one using 'init'.")
        return

    print(f"[*] Checking integrity for directory: {directory}")
    current_state = {}
    for dirpath, dirnames, filenames in os.walk(directory):

        dirnames[:] = [d for d in dirnames if not is_excluded(
            os.path.join(dirpath, d), {'dirs': exclusions['dirs'], 'files': []})]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if is_excluded(filepath, exclusions):
                continue

            file_hash = get_file_hash(filepath)
            if file_hash:
                relative_path = os.path.relpath(filepath, directory)
                current_state[relative_path] = file_hash

    baseline_files = set(baseline.keys())
    current_files = set(current_state.keys())

    new_files = current_files - baseline_files
    deleted_files = baseline_files - current_files

    modified_files = set()
    for file in baseline_files.intersection(current_files):
        if baseline[file] != current_state[file]:
            modified_files.add(file)

    report_header = f"Integrity Check Report ({datetime.now()})"
    logger.info("\n" + "-"*len(report_header) + "\n" +
                report_header + "\n" + "-"*len(report_header))

    if not new_files and not deleted_files and not modified_files:
        logger.info("Everything is OK. No changes detected.")
    else:
        if new_files:
            logger.warning("New files detected (%d):", len(new_files))
            for file in new_files:
                logger.warning("  - %s", file)

        if deleted_files:
            logger.warning("Deleted files detected (%d):", len(deleted_files))
            for file in deleted_files:
                logger.warning("  - %s", file)

        if modified_files:
            logger.warning("Modified files detected (%d):",
                           len(modified_files))
            for file in modified_files:
                logger.warning("  - %s", file)

    logger.info("-" * len(report_header))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("mode", choices=[
                        "init", "check"], help="The mode to run the script in: 'init' or 'check'")
    parser.add_argument("directory", help="The directory to monitor")
    args = parser.parse_args()

    exclusions = load_config()

    if not os.path.isdir(args.directory):
        print(f"[!] Error: Directory '{args.directory}' not found.")
    elif args.mode == "init":
        create_basline(args.directory, exclusions)
    elif args.mode == "check":
        check_integrity(args.directory, exclusions)
