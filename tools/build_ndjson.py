#!/usr/bin/env python3
import argparse
import json
import os
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Iterable, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build NDJSON from Ghidra export.v5.json outputs")
    parser.add_argument("--input", required=True, help="Root directory containing Ghidra exports")
    parser.add_argument("--output", required=True, help="Destination NDJSON file path")
    return parser.parse_args()


def find_export_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith(".json"):
                continue
            if name != "export.v5.json":
                # Ignore unrelated JSON files to avoid mixing schemas
                continue
            yield Path(dirpath) / name


def normalize_binary(meta: Dict[str, Any]) -> Dict[str, Any]:
    template = OrderedDict(
        [
            ("name", ""),
            ("path", ""),
            ("md5", ""),
            ("language_id", ""),
            ("compiler", ""),
        ]
    )
    meta = meta or {}
    for key in template:
        template[key] = meta.get(key, "") if meta.get(key) is not None else ""
    return template


def normalize_sections(sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    default_map = {
        "name": "",
        "start": "",
        "end": "",
        "size": None,
        "read": None,
        "write": None,
        "execute": None,
        "initialized": None,
    }
    for sec in sections or []:
        entry = OrderedDict()
        for key, default in default_map.items():
            value = sec.get(key) if sec else None
            entry[key] = default if value is None else value
        normalized.append(entry)
    return normalized


def normalize_imports(imports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    default_map = {
        "name": "",
        "address": "",
        "library": "",
        "label": "",
        "is_function": None,
        "is_data": None,
    }
    for imp in imports or []:
        entry = OrderedDict()
        for key, default in default_map.items():
            value = imp.get(key) if imp else None
            entry[key] = default if value is None else value
        normalized.append(entry)
    return normalized


def normalize_strings(strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    default_map = {"address": "", "value": "", "length": None, "type": ""}
    for s in strings or []:
        entry = OrderedDict()
        for key, default in default_map.items():
            value = s.get(key) if s else None
            entry[key] = default if value is None else value
        normalized.append(entry)
    return normalized


def normalize_asm(instrs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    default_map = {"address": "", "mnemonic": "", "text": ""}
    for ins in instrs or []:
        entry = OrderedDict()
        for key, default in default_map.items():
            value = ins.get(key) if ins else None
            entry[key] = default if value is None else value
        normalized.append(entry)
    return normalized


def normalize_xrefs(xrefs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    default_map = {"from": "", "to": "", "type": "", "is_call": None, "is_data": None}
    for xr in xrefs or []:
        entry = OrderedDict()
        for key, default in default_map.items():
            value = xr.get(key) if xr else None
            entry[key] = default if value is None else value
        normalized.append(entry)
    return normalized


def normalize_cfg(cfg: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    default_map = {"from": "", "to": "", "type": ""}
    for edge in cfg or []:
        entry = OrderedDict()
        for key, default in default_map.items():
            value = edge.get(key) if edge else None
            entry[key] = default if value is None else value
        normalized.append(entry)
    return normalized


def normalize_function_doc(
    binary: Dict[str, Any],
    sections: List[Dict[str, Any]],
    imports: List[Dict[str, Any]],
    strings: List[Dict[str, Any]],
    func: Dict[str, Any],
) -> OrderedDict:
    name = func.get("name") if func else ""
    entry = func.get("entry") if func else ""
    size = func.get("size") if func else None
    prototype = func.get("prototype") if func else ""
    calling_convention = func.get("calling_convention") if func else ""
    decompiled = func.get("decompiled") if func else None
    asm_list = normalize_asm(func.get("asm") if func else [])
    xrefs_list = normalize_xrefs(func.get("xrefs") if func else [])
    cfg_list = normalize_cfg(func.get("cfg") if func else [])

    doc = OrderedDict()
    doc["id"] = f"{binary.get('name', '')}:{entry}" if entry else f"{binary.get('name', '')}:"
    doc["binary"] = normalize_binary(binary)
    doc["sections"] = normalize_sections(sections)
    doc["imports"] = normalize_imports(imports)
    doc["strings"] = normalize_strings(strings)
    doc["name"] = name if name is not None else ""
    doc["entry"] = entry if entry is not None else ""
    doc["size"] = size if size is not None else None
    doc["prototype"] = prototype if prototype is not None else ""
    doc["calling_convention"] = calling_convention if calling_convention is not None else ""
    doc["decompiled"] = decompiled if decompiled is not None else None
    doc["asm"] = asm_list
    doc["xrefs"] = xrefs_list
    doc["cfg"] = cfg_list
    return doc


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_ndjson(docs: Iterable[OrderedDict], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as f:
        for doc in docs:
            json.dump(doc, f, ensure_ascii=False)
            f.write("\n")


def build_documents(export_paths: Iterable[Path]) -> List[OrderedDict]:
    documents: List[OrderedDict] = []
    for path in export_paths:
        data = load_json(path)
        binary = data.get("binary") or {}
        sections = data.get("sections") or []
        imports = data.get("imports") or []
        strings = data.get("strings") or []
        functions = data.get("functions") or []
        for func in functions:
            documents.append(
                normalize_function_doc(binary, sections, imports, strings, func)
            )
    return documents


def main() -> None:
    args = parse_args()
    root = Path(args.input)
    if not root.is_dir():
        raise SystemExit(f"Input root does not exist or is not a directory: {root}")

    export_files = list(find_export_files(root))
    if not export_files:
        raise SystemExit(f"No export.v5.json files found under {root}")

    documents = build_documents(export_files)
    write_ndjson(documents, Path(args.output))


if __name__ == "__main__":
    main()
