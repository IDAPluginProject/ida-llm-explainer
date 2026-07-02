#!/usr/bin/env python3
"""Build the distributable plugin.zip for the Hex-Rays plugin repository.

Per https://hcli.docs.hex-rays.com/reference/plugin-packaging-and-format/,
ida-plugin.json must sit at the ROOT of the archive, alongside the entry
point file. GitHub's auto-generated "Source code (zip)" release asset wraps
everything in a top-level "<repo>-<tag>/" folder, which breaks that
requirement - this script builds the correct flat archive instead, to be
attached as its own release asset.

Usage: python package.py
Output: dist/<plugin-name>-<version>.zip
"""

import json
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "ida-plugin.json"


def main():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    plugin = manifest["plugin"]
    name = plugin["name"]
    version = plugin["version"]
    entry_point = plugin["entryPoint"]

    entry_path = ROOT / entry_point
    if not entry_path.is_file():
        raise SystemExit("Entry point '%s' not found next to ida-plugin.json" % entry_point)

    dist_dir = ROOT / "dist"
    dist_dir.mkdir(exist_ok=True)
    out_path = dist_dir / ("%s-%s.zip" % (name, version))

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(MANIFEST_PATH, arcname="ida-plugin.json")
        zf.write(entry_path, arcname=entry_point)

    print("Wrote %s" % out_path)
    print("Contents:")
    with zipfile.ZipFile(out_path) as zf:
        for info in zf.infolist():
            print("  %s" % info.filename)


if __name__ == "__main__":
    main()
