"""
Local CVE repository management (clone/pull) and keyword search utilities.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
from typing import Iterable, List, Optional

from git import Repo, GitCommandError, RemoteProgress
from tqdm import tqdm

from .paths import get_cve_repo_dir, get_cve_local_dir


class CloneProgress(RemoteProgress):
    def update(self, op_code, cur_count, max_count=None, message=""):
        if max_count:
            try:
                percent = (cur_count / max_count) * 100
            except Exception:
                percent = 0.0
            print(f"🔄 Progress: {percent:.2f}% - {message}", end="\r")
        else:
            print(f"🔄 {message}", end="\r")


def clone_cvelistV5_repo(*, config: Optional[dict] = None) -> Optional[str]:
    """
    Clone or update the CVEProject/cvelistV5 repository into the configured local directory.

    Returns the local directory path on success, or None on failure.
    """
    local_dir = get_cve_repo_dir(config)
    repo_url = "https://github.com/CVEProject/cvelistV5.git"

    os.makedirs(local_dir, exist_ok=True)
    git_dir = os.path.join(local_dir, ".git")

    if not os.path.exists(git_dir):
        try:
            print(f"📥 Cloning CVE List V5 into '{local_dir}'.")
            print("⚠️ Warning: The repository is several GB in size and the download may take a while.")
            Repo.clone_from(repo_url, local_dir, progress=CloneProgress())
            print("\n✅ CVE List V5 cloned successfully.")
        except GitCommandError as e:
            print(f"❌ Error cloning cvelistV5: {e}")
            return None
    else:
        try:
            repo = Repo(local_dir)
            if repo.bare:
                print(f"❌ Repository at '{local_dir}' is bare. Cannot pull updates.")
                return None
            print(f"📥 Pulling updates in '{local_dir}'...")
            repo.remotes.origin.pull()
            print("✅ Repository updated successfully.")
        except GitCommandError as e:
            print(f"❌ Error pulling updates: {e}")
            return None

    return local_dir


def _file_contains_all_keywords(file_path: str, keywords_lower: List[str]) -> Optional[str]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().lower()
            if all(kw in content for kw in keywords_lower):
                return os.path.splitext(os.path.basename(file_path))[0]
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return None


def grep_local_db(keywords: Iterable[str], *, config: Optional[dict] = None) -> Optional[List[str]]:
    """
    Search the local cvelistV5 JSON files for occurrences of all provided keywords.

    Returns a list of CVE IDs (filenames) when matches are found, otherwise None.
    """
    local_dir = get_cve_local_dir(config)
    if not os.path.exists(local_dir):
        print("Local CVE database not found.")
        return None

    keywords_lower = [kw.lower() for kw in (list(keywords) if not isinstance(keywords, str) else [keywords])]
    print(f"┌───[ 🕵️ Searching local database for keywords: {', '.join(keywords_lower)} ]")

    json_files: List[str] = []
    for root, _, files in os.walk(local_dir):
        for filename in files:
            if filename.endswith(".json"):
                json_files.append(os.path.join(root, filename))

    matching_files: List[str] = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for result in tqdm(
            executor.map(lambda p: _file_contains_all_keywords(p, keywords_lower), json_files),
            total=len(json_files),
            desc="Processing CVE files",
        ):
            if result is not None:
                matching_files.append(result)

    return matching_files if matching_files else None
