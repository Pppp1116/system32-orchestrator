#!/usr/bin/env jython
# -*- coding: utf-8 -*-

import os
import sys
import json
import traceback
import codecs

from ghidra.app.decompiler import DecompInterface


def safe_str(obj):
    try:
        if obj is None:
            return None
        return str(obj)
    except Exception:
        return None


def parse_flags(args):
    """
    Parse command-line flags of the form:
      <out_root> [--include-decompiled true/false] [--include-asm true/false] ...
    """
    flags = {
        "include_decompiled": True,
        "include_asm": True,
        "include_strings": True,
        "include_xrefs": True,
        "include_cfg": True,
    }

    if not args:
        return None, flags

    out_root = args[0]
    i = 1
    while i < len(args):
        key = args[i]
        if key.startswith("--") and (i + 1) < len(args):
            val = args[i + 1]
            k = key[2:].replace("-", "_")
            if k in flags:
                v = val.lower()
                flags[k] = (v in ("1", "true", "yes", "on"))
            i += 2
        else:
            i += 1

    return out_root, flags


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def mk_addr_str(addr):
    try:
        return "0x%x" % addr.getOffset()
    except Exception:
        return safe_str(addr)


def export_sections(program):
    """
    Export memory sections / blocks. Use Memory.getBlocks(), which returns
    a Java array that is directly iterable in Jython. The previous version
    tried to call .hasNext() on it, which raised:
        'array.array' object has no attribute 'hasNext'
    """
    sections = []
    try:
        mem = program.getMemory()
    except Exception:
        return sections

    try:
        for blk in mem.getBlocks():
            try:
                sections.append({
                    "name": safe_str(blk.getName()),
                    "start": safe_str(blk.getStart()),
                    "end": safe_str(blk.getEnd()),
                    "size": int(blk.getSize()),
                    "read": bool(blk.isRead()),
                    "write": bool(blk.isWrite()),
                    "execute": bool(blk.isExecute()),
                    "initialized": bool(blk.isInitialized()),
                })
            except Exception:
                # Skip individual problematic blocks
                continue
    except Exception:
        # If iteration fails completely, just return what we have
        pass

    return sections


def export_imports(program):
    """
    Export imported symbols using the SymbolTable external symbols.
    This avoids relying on ExternalManager internals that changed across versions.
    """
    imports = []
    try:
        symtab = program.getSymbolTable()
        it = symtab.getExternalSymbols()
    except Exception:
        return imports

    try:
        while it.hasNext():
            sym = it.next()
            try:
                ext_loc = sym.getExternalLocation()
                imports.append({
                    "name": safe_str(sym.getName()),
                    "address": mk_addr_str(sym.getAddress()),
                    "library": safe_str(ext_loc.getLibraryName()) if ext_loc else None,
                    "label": safe_str(ext_loc.getLabel()) if ext_loc else None,
                    "is_function": bool(sym.isFunction()),
                    "is_data": bool(sym.isData()),
                })
            except Exception:
                continue
    except Exception:
        pass

    return imports


def setup_decompiler(program):
    iface = DecompInterface()
    iface.openProgram(program)
    return iface


def decompile_function(iface, func, timeout_ms=0):
    res = iface.decompileFunction(func, timeout_ms, monitor)
    if not res or not res.getDecompiledFunction():
        return None
    try:
        return res.getDecompiledFunction().getC()
    except Exception:
        return None


def export_functions(program, flags, monitor):
    listing = program.getListing()
    funcs = []

    # Decompiler (optional)
    iface = None
    if flags.get("include_decompiled", True):
        try:
            iface = setup_decompiler(program)
        except Exception:
            iface = None

    try:
        func_mgr = program.getFunctionManager()
        it = func_mgr.getFunctions(True)
    except Exception:
        return funcs

    func_count = 0

    while it.hasNext():
        if monitor is not None and monitor.isCancelled():
            break

        func = it.next()
        func_count += 1

        try:
            f_entry = func.getEntryPoint()
            f_name = func.getName()
            proto = func.getSignature()
            calling = func.getCallingConventionName()

            # Decompilation
            decompiled = None
            if iface is not None and flags.get("include_decompiled", True):
                try:
                    decompiled = decompile_function(iface, func)
                except Exception:
                    decompiled = None

            # Assembly (instruction list)
            asm_list = []
            if flags.get("include_asm", True):
                try:
                    instr_iter = listing.getInstructions(func.getBody(), True)
                    while instr_iter.hasNext():
                        ins = instr_iter.next()
                        try:
                            asm_list.append({
                                "address": mk_addr_str(ins.getAddress()),
                                "mnemonic": safe_str(ins.getMnemonicString()),
                                "text": safe_str(ins.toString()),
                            })
                        except Exception:
                            continue
                except Exception:
                    asm_list = []

            # Xrefs from/to function body
            xrefs = []
            if flags.get("include_xrefs", True):
                try:
                    ref_mgr = program.getReferenceManager()
                    body = func.getBody().getAddresses(True)
                    while body.hasNext():
                        addr = body.next()
                        # From this address
                        try:
                            from_refs = ref_mgr.getReferencesFrom(addr)
                            for r in from_refs:
                                try:
                                    xrefs.append({
                                        "from": mk_addr_str(r.getFromAddress()),
                                        "to": mk_addr_str(r.getToAddress()),
                                        "type": safe_str(r.getReferenceType().getName()),
                                        "is_call": bool(r.getReferenceType().isCall()),
                                        "is_data": bool(r.getReferenceType().isData()),
                                    })
                                except Exception:
                                    continue
                        except Exception:
                            pass
                        # To this address
                        try:
                            to_refs = ref_mgr.getReferencesTo(addr)
                            for r in to_refs:
                                try:
                                    xrefs.append({
                                        "from": mk_addr_str(r.getFromAddress()),
                                        "to": mk_addr_str(r.getToAddress()),
                                        "type": safe_str(r.getReferenceType().getName()),
                                        "is_call": bool(r.getReferenceType().isCall()),
                                        "is_data": bool(r.getReferenceType().isData()),
                                    })
                                except Exception:
                                    continue
                        except Exception:
                            pass
                except Exception:
                    xrefs = []

            # Simple CFG: successors by outgoing references on instructions
            cfg_edges = []
            if flags.get("include_cfg", True):
                try:
                    ref_mgr = program.getReferenceManager()
                    instr_iter = listing.getInstructions(func.getBody(), True)
                    seen_edges = set()
                    while instr_iter.hasNext():
                        ins = instr_iter.next()
                        from_a = ins.getAddress()
                        try:
                            refs = ref_mgr.getReferencesFrom(from_a)
                        except Exception:
                            continue
                        for r in refs:
                            try:
                                if not r.getReferenceType().isFlow():
                                    continue
                                to_a = r.getToAddress()
                                key = (from_a, to_a)
                                if key in seen_edges:
                                    continue
                                seen_edges.add(key)
                                cfg_edges.append({
                                    "from": mk_addr_str(from_a),
                                    "to": mk_addr_str(to_a),
                                    "type": safe_str(r.getReferenceType().getName()),
                                })
                            except Exception:
                                continue
                except Exception:
                    cfg_edges = []

            funcs.append({
                "name": f_name,
                "entry": mk_addr_str(f_entry),
                "size": int(func.getBody().getNumAddresses()),
                "prototype": safe_str(proto),
                "calling_convention": safe_str(calling),
                "decompiled": decompiled,
                "asm": asm_list,
                "xrefs": xrefs,
                "cfg": cfg_edges,
            })

        except Exception:
            # Do not kill the whole export because of a single bad function
            continue

    return funcs


def export_strings(program, listing, monitor):
    """
    Export defined strings using Listing.getDefinedStrings(True).
    The old version walked all defined data and tried to treat any
    string-like datatype as a string. That still works, but using
    getDefinedStrings() is simpler and avoids relying on ProgramDB
    internals that changed between Ghidra versions.
    """
    strings = []
    try:
        it = listing.getDefinedStrings(True)  # forward iteration
    except Exception:
        return strings

    try:
        while it.hasNext():
            if monitor is not None and monitor.isCancelled():
                break
            try:
                s = it.next()
                strings.append({
                    "address": safe_str(s.getAddress()),
                    "value": safe_str(s.getString(None)),  # default charset
                    "length": int(s.getLength()),
                    "type": safe_str(s.getDataType().getName()),
                })
            except Exception:
                # Skip problematic entries but keep going
                continue
    except Exception:
        # If the iterator itself fails, just return what we collected
        pass

    return strings


def main():
    # Debug: garantir que o script arrancou e recebeu o argumento
    args = getScriptArgs()  # fornecido pelo Ghidra Jython
    print("export_full_json.py: starting, args = %r" % (args,))

    if len(args) < 1:
        print("Usage: export_full_json.py <output_root> [--include-decompiled true/false] "
              "[--include-asm true/false] [--strings true/false] [--xrefs true/false] [--cfg true/false]")
        return

    out_root, flags = parse_flags(args)
    print("export_full_json.py: out_root = %r" % out_root)
    print("export_full_json.py: flags = %r" % flags)

    program = currentProgram
    listing = program.getListing()

    bin_path = safe_str(program.getExecutablePath())
    bin_name = os.path.basename(bin_path) if bin_path else "unknown_binary"
    bin_md5 = safe_str(program.getExecutableMD5())
    lang_id = safe_str(program.getLanguageID())
    compiler = safe_str(program.getCompiler())

    out_dir = os.path.join(out_root, bin_name)
    ensure_dir(out_dir)
    out_file = os.path.join(out_dir, "export.v5.json")

    root = {
        "binary": {
            "name": bin_name,
            "path": bin_path,
            "md5": bin_md5,
            "language_id": lang_id,
            "compiler": compiler,
        },
        "sections": [],
        "imports": [],
        "functions": [],
        "strings": [],
    }

    # SECTIONS
    try:
        root["sections"] = export_sections(program)
    except Exception:
        print("WARN: export_sections() falhou")
        traceback.print_exc()

    # IMPORTS
    try:
        root["imports"] = export_imports(program)
    except Exception:
        print("WARN: export_imports() falhou")
        traceback.print_exc()

    # FUNCTIONS (+ ASM, XREFS, CFG, DECOMP)
    try:
        root["functions"] = export_functions(program, flags, monitor)
    except Exception:
        print("WARN: export_functions() falhou")
        traceback.print_exc()

    # STRINGS
    if flags.get("include_strings", True):
        try:
            root["strings"] = export_strings(program, listing, monitor)
        except Exception:
            print("WARN: export_strings() falhou")
            traceback.print_exc()

    # Escrever JSON
    try:
        # usar utf-8 sempre
        with codecs.open(out_file, "w", encoding="utf-8") as f:
            json.dump(root, f, indent=2, sort_keys=False, ensure_ascii=False)
        print("export_full_json.py: wrote %r" % out_file)
    except Exception:
        print("ERROR: failed to write JSON to %r" % out_file)
        traceback.print_exc()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
