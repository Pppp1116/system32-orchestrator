#!/usr/bin/env python3
import argparse
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from tqdm import tqdm

    TQDM_AVAILABLE = True
except Exception:
    TQDM_AVAILABLE = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build NDJSON from Ghidra export.v5.json outputs"
    )
    parser.add_argument("--input", required=True, help="Root directory containing Ghidra exports")
    parser.add_argument("--output", required=True, help="Destination NDJSON file path")
    parser.add_argument(
        "--log-every",
        type=int,
        default=50,
        help="Log progress every N files (default: 50)",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show a progress bar when tqdm is available",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=0,
        metavar="N",
        help="Enable threaded JSON loading with N worker threads",
    )
    parser.add_argument(
        "--only-binary",
        help="Only emit functions belonging to the given binary name",
    )
    parser.add_argument(
        "--only-path",
        help="Restrict processing to export files under the given subdirectory",
    )
    return parser.parse_args()


def find_export_files(root: Path, only_path: Optional[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith(".json"):
                continue
            if name != "export.v5.json":
                # Ignore unrelated JSON files to avoid mixing schemas
                continue
            full_path = Path(dirpath) / name
            if only_path:
                try:
                    full_path.relative_to(root / only_path)
                except ValueError:
                    continue
            yield full_path


logger = logging.getLogger("build_ndjson")


@dataclass(frozen=True)
class FieldSpec:
    name: str
    types: Tuple[type, ...]
    default: Any
    validator: Optional[Any] = None
    required: bool = False


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _validate_address(value: str, context: str) -> str:
    if not value:
        logger.warning("Missing address in %s", context)
        return ""
    if isinstance(value, str):
        if not value.startswith("0x"):
            logger.warning("Non-hex address '%s' in %s", value, context)
        return value
    logger.warning("Unexpected address type %s in %s", type(value).__name__, context)
    return _as_str(value)


def _validate_bool(value: Any, context: str, field: str) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    logger.warning("Expected bool for %s in %s, got %r", field, context, value)
    return bool(value)


def _validate_str(value: Any, context: str, field: str) -> str:
    if value is None:
        logger.warning("Missing string for %s in %s", field, context)
        return ""
    if not isinstance(value, str):
        logger.warning("Expected string for %s in %s, got %s", field, context, type(value).__name__)
    return _as_str(value)


def _validate_int(value: Any, context: str, field: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    logger.warning("Expected int for %s in %s, got %s", field, context, type(value).__name__)
    try:
        return int(value)
    except Exception:
        return None


BINARY_SCHEMA: Sequence[FieldSpec] = (
    FieldSpec("name", (str,), "", required=True),
    FieldSpec("path", (str,), "", required=True),
    FieldSpec("md5", (str,), ""),
    FieldSpec("language_id", (str,), ""),
    FieldSpec("compiler", (str,), ""),
)

SECTION_SCHEMA: Sequence[FieldSpec] = (
    FieldSpec("name", (str,), "", lambda v, c: _validate_str(v, c, "section.name"), True),
    FieldSpec("start", (str,), "", _validate_address, True),
    FieldSpec("end", (str,), "", _validate_address, True),
    FieldSpec("size", (int,), None, lambda v, c: _validate_int(v, c, "section.size")),
    FieldSpec("read", (bool,), None, lambda v, c: _validate_bool(v, c, "section.read")),
    FieldSpec("write", (bool,), None, lambda v, c: _validate_bool(v, c, "section.write")),
    FieldSpec("execute", (bool,), None, lambda v, c: _validate_bool(v, c, "section.execute")),
    FieldSpec("initialized", (bool,), None, lambda v, c: _validate_bool(v, c, "section.initialized")),
)

IMPORT_SCHEMA: Sequence[FieldSpec] = (
    FieldSpec("name", (str,), "", lambda v, c: _validate_str(v, c, "import.name"), True),
    FieldSpec("address", (str,), "", _validate_address, True),
    FieldSpec("library", (str,), "", lambda v, c: _validate_str(v, c, "import.library")),
    FieldSpec("label", (str,), "", lambda v, c: _validate_str(v, c, "import.label")),
    FieldSpec("is_function", (bool,), None, lambda v, c: _validate_bool(v, c, "import.is_function")),
    FieldSpec("is_data", (bool,), None, lambda v, c: _validate_bool(v, c, "import.is_data")),
)

STRING_SCHEMA: Sequence[FieldSpec] = (
    FieldSpec("address", (str,), "", _validate_address, True),
    FieldSpec("value", (str,), "", lambda v, c: _validate_str(v, c, "string.value"), True),
    FieldSpec("length", (int,), None, lambda v, c: _validate_int(v, c, "string.length")),
    FieldSpec("type", (str,), "", lambda v, c: _validate_str(v, c, "string.type")),
)

ASM_SCHEMA: Sequence[FieldSpec] = (
    FieldSpec("address", (str,), "", _validate_address, True),
    FieldSpec("mnemonic", (str,), "", lambda v, c: _validate_str(v, c, "asm.mnemonic"), True),
    FieldSpec("text", (str,), "", lambda v, c: _validate_str(v, c, "asm.text"), True),
)

XREF_SCHEMA: Sequence[FieldSpec] = (
    FieldSpec("from", (str,), "", _validate_address, True),
    FieldSpec("to", (str,), "", _validate_address, True),
    FieldSpec("type", (str,), "", lambda v, c: _validate_str(v, c, "xref.type"), True),
    FieldSpec("is_call", (bool,), None, lambda v, c: _validate_bool(v, c, "xref.is_call")),
    FieldSpec("is_data", (bool,), None, lambda v, c: _validate_bool(v, c, "xref.is_data")),
)

CFG_SCHEMA: Sequence[FieldSpec] = (
    FieldSpec("from", (str,), "", _validate_address, True),
    FieldSpec("to", (str,), "", _validate_address, True),
    FieldSpec("type", (str,), "", lambda v, c: _validate_str(v, c, "cfg.type"), True),
)


def apply_schema(
    record: Optional[Dict[str, Any]],
    schema: Sequence[FieldSpec],
    context: str,
) -> OrderedDict:
    normalized = OrderedDict()
    source = record or {}
    for field in schema:
        value = source.get(field.name)
        if value is None:
            if field.required:
                logger.warning("Missing field %s in %s", field.name, context)
            normalized[field.name] = field.default
            continue

        if not isinstance(value, field.types):
            logger.warning(
                "Incorrect type for %s in %s: expected %s, got %s",
                field.name,
                context,
                ",".join(t.__name__ for t in field.types),
                type(value).__name__,
            )
        if field.validator:
            normalized[field.name] = field.validator(value, context)
        elif isinstance(value, str):
            normalized[field.name] = _as_str(value)
        else:
            normalized[field.name] = value
    return normalized


def normalize_sections(sections: List[Dict[str, Any]], context: str) -> List[Dict[str, Any]]:
    return [apply_schema(sec, SECTION_SCHEMA, f"{context}.section[{idx}]") for idx, sec in enumerate(sections or [])]


def normalize_imports(imports: List[Dict[str, Any]], context: str) -> List[Dict[str, Any]]:
    return [apply_schema(imp, IMPORT_SCHEMA, f"{context}.import[{idx}]") for idx, imp in enumerate(imports or [])]


def normalize_strings(strings: List[Dict[str, Any]], context: str) -> List[Dict[str, Any]]:
    return [apply_schema(s, STRING_SCHEMA, f"{context}.string[{idx}]") for idx, s in enumerate(strings or [])]


def normalize_asm(instrs: List[Dict[str, Any]], context: str) -> List[Dict[str, Any]]:
    return [apply_schema(ins, ASM_SCHEMA, f"{context}.asm[{idx}]") for idx, ins in enumerate(instrs or [])]


def normalize_xrefs(xrefs: List[Dict[str, Any]], context: str) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for idx, xr in enumerate(xrefs or []):
        normalized.append(
            apply_schema(xr, XREF_SCHEMA, f"{context}.xref[{idx}]")
        )
    return normalized


def normalize_cfg(cfg: List[Dict[str, Any]], context: str) -> List[Dict[str, Any]]:
    return [apply_schema(edge, CFG_SCHEMA, f"{context}.cfg[{idx}]") for idx, edge in enumerate(cfg or [])]


def normalize_function_doc(
    binary: Dict[str, Any],
    sections: List[Dict[str, Any]],
    imports: List[Dict[str, Any]],
    strings: List[Dict[str, Any]],
    func: Dict[str, Any],
) -> OrderedDict:
    context = f"function[{func.get('name', '') or func.get('entry', '')}]" if func else "function"
    name = _validate_str(func.get("name"), context, "function.name") if func else ""
    entry = _validate_address(func.get("entry"), context) if func else ""
    size = _validate_int(func.get("size"), context, "function.size") if func else None
    prototype = _validate_str(func.get("prototype"), context, "function.prototype") if func else ""
    calling_convention = _validate_str(
        func.get("calling_convention"), context, "function.calling_convention"
    ) if func else ""
    decompiled = func.get("decompiled") if func else None
    if decompiled is not None and isinstance(decompiled, str) and not decompiled.strip():
        logger.warning("Empty decompiled pseudocode for %s", context)
    asm_list = normalize_asm(func.get("asm") if func else [], context)
    xrefs_list = normalize_xrefs(func.get("xrefs") if func else [], context)
    cfg_list = normalize_cfg(func.get("cfg") if func else [], context)

    doc = OrderedDict()
    doc["id"] = f"{binary.get('name', '')}:{entry}" if entry else f"{binary.get('name', '')}:"
    doc["binary"] = apply_schema(binary, BINARY_SCHEMA, f"{context}.binary")
    doc["sections"] = normalize_sections(sections, context)
    doc["imports"] = normalize_imports(imports, context)
    doc["strings"] = normalize_strings(strings, context)
    doc["name"] = name
    doc["entry"] = entry
    doc["size"] = size
    doc["prototype"] = prototype
    doc["calling_convention"] = calling_convention
    doc["decompiled"] = decompiled if isinstance(decompiled, (str, type(None))) else _as_str(decompiled)
    doc["asm"] = asm_list
    doc["xrefs"] = xrefs_list
    doc["cfg"] = cfg_list
    return doc


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse JSON %s: %s", path, exc)
    except OSError as exc:
        logger.error("Failed to read %s: %s", path, exc)
    return None


def write_ndjson(docs: Iterable[OrderedDict], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as f:
        for doc in docs:
            json.dump(doc, f, ensure_ascii=False, sort_keys=False)
            f.write("\n")


def iter_exports_with_loader(
    export_paths: Sequence[Path], threads: int
) -> Iterable[Tuple[Path, Optional[Dict[str, Any]]]]:
    if threads > 0:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {executor.submit(load_json, p): p for p in export_paths}
            for future in as_completed(future_map):
                path = future_map[future]
                try:
                    yield path, future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error("Unexpected error loading %s: %s", path, exc)
                    yield path, None
    else:
        for path in export_paths:
            yield path, load_json(path)


def build_documents(
    export_paths: Sequence[Path],
    only_binary: Optional[str],
    threads: int,
    progress_bar: bool,
    log_every: int,
) -> List[OrderedDict]:
    documents: List[OrderedDict] = []
    total = len(export_paths)
    iterator = iter_exports_with_loader(export_paths, threads)
    use_tqdm = progress_bar and TQDM_AVAILABLE
    wrapped_iter = tqdm(iterator, total=total, disable=not use_tqdm) if total else iterator

    for idx, (path, data) in enumerate(wrapped_iter, start=1):
        if data is None:
            continue
        binary = data.get("binary") or {}
        if not isinstance(binary, dict):
            logger.warning("Binary metadata malformed in %s", path)
            binary = {}
        if only_binary and binary.get("name") != only_binary:
            continue

        sections = data.get("sections") or []
        imports = data.get("imports") or []
        strings = data.get("strings") or []

        if not isinstance(sections, list):
            logger.warning("Sections array malformed in %s", path)
            sections = []
        if not isinstance(imports, list):
            logger.warning("Imports array malformed in %s", path)
            imports = []
        if not isinstance(strings, list):
            logger.warning("Strings array malformed in %s", path)
            strings = []
        functions = data.get("functions") or []

        if not isinstance(functions, list):
            logger.warning("Functions array malformed in %s", path)
            functions = []

        for func in functions:
            if not isinstance(func, dict):
                logger.warning("Skipping non-dict function entry in %s", path)
                continue
            documents.append(
                normalize_function_doc(binary, sections, imports, strings, func)
            )

        if not use_tqdm and idx % max(log_every, 1) == 0:
            logger.info("Processed %d/%d files", idx, total)

    return documents


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    args = parse_args()
    root = Path(args.input)
    if not root.is_dir():
        raise SystemExit(f"Input root does not exist or is not a directory: {root}")

    export_files = list(find_export_files(root, args.only_path))
    if not export_files:
        raise SystemExit(f"No export.v5.json files found under {root}")

    if args.progress and not TQDM_AVAILABLE:
        logger.warning("tqdm not installed; progress bar disabled")

    documents = build_documents(
        export_files,
        args.only_binary,
        max(args.threads, 0),
        args.progress,
        max(args.log_every, 1),
    )
    write_ndjson(documents, Path(args.output))


if __name__ == "__main__":
    main()
