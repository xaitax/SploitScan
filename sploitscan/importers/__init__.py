from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Callable, Iterable, List, Optional


_CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}$")


def is_valid_cve_id(cve_id: str) -> bool:
    return bool(_CVE_REGEX.match(cve_id))


def is_plaintext_cve_list(file_path: str) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for _ in range(10):
                line = f.readline()
                if not line:
                    break
                val = line.strip().upper()
                if val and not is_valid_cve_id(val):
                    return False
        return True
    except Exception:
        return False


def parse_plaintext_cve_list(f) -> List[str]:
    return [line.strip().upper() for line in f if is_valid_cve_id(line.strip().upper())]


def parse_nessus_file(f) -> List[str]:
    tree = ET.parse(f)
    root = tree.getroot()
    return [
        (cve.text or "").strip().upper()
        for report_item in root.findall(".//ReportItem")
        for cve in report_item.findall("cve")
        if is_valid_cve_id((cve.text or "").strip().upper())
    ]


def parse_nexpose_file(f) -> List[str]:
    tree = ET.parse(f)
    root = tree.getroot()
    return [
        (link.get("LinkTitle") or "").upper()
        for link in root.findall(".//URLLink")
        if (link.get("LinkTitle") or "").startswith("CVE-")
    ]


def parse_openvas_file(f) -> List[str]:
    tree = ET.parse(f)
    root = tree.getroot()
    return [
        (ref.attrib.get("id") or "").upper()
        for ref in root.findall(".//ref[@type='cve']")
        if is_valid_cve_id((ref.attrib.get("id") or "").upper())
    ]


def parse_docker_file(f) -> List[str]:
    data = json.load(f)
    return [
        (rule.get("id") or "").upper()
        for run in data.get("runs", [])
        for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        if (rule.get("id") or "").startswith("CVE-")
    ]


def import_file(file_path: str, parse_function: Callable) -> List[str]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            cve_ids = parse_function(f)
        return list(set(cve_ids))
    except ET.ParseError as e:
        print(f"❌ Error parsing the file '{file_path}': {e}")
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing the JSON file '{file_path}': {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred while processing '{file_path}': {e}")
    return []


def import_vulnerability_data(file_path: str, file_type: Optional[str] = None) -> List[str]:
    if not file_path:
        return []

    if not file_type:
        if is_plaintext_cve_list(file_path):
            return import_file(file_path, parse_plaintext_cve_list)
        else:
            print(
                f"❌ Error: The file '{file_path}' does not appear to be a valid list of CVEs. "
                "Please specify the correct file type using the --type option."
            )
            return []

    if file_type == "nessus":
        return import_file(file_path, parse_nessus_file)
    if file_type == "nexpose":
        return import_file(file_path, parse_nexpose_file)
    if file_type == "openvas":
        return import_file(file_path, parse_openvas_file)
    if file_type == "docker":
        return import_file(file_path, parse_docker_file)

    print(f"❌ Unsupported file type: {file_type}")
    return []


def import_vulnerability_data_from_dir(dir_path: str) -> List[str]:
    if not os.path.exists(dir_path):
        print(f"❌ Error: The directory '{dir_path}' does not exist.")
        return []
    if not os.path.isdir(dir_path):
        print(f"❌ Error: '{dir_path}' is not a directory. Use --input-dir with a directory path.")
        return []

    p = pathlib.Path(dir_path, encoding='utf-8').glob('**/*')
    reports_list = [str(x) for x in p if x.is_file()]

    cve_ids_list = []

    for report_path in reports_list:
        cve_ids_list.extend(import_file(report_path, parse_cve_in_report))

    unique_cve_ids = list(set(cve_ids_list))
    print(f"📥 Successfully imported {len(unique_cve_ids)} CVE(s) from '{dir_path}'\n")
    return unique_cve_ids


def parse_cve_in_report(file):
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    try:
        content = file.read()
        return [cve.upper() for cve in re.findall(cve_pattern, content, re.IGNORECASE)]

    except Exception as e:
        print(f"❌ Error reading file '{file}': {e}")
        return []
