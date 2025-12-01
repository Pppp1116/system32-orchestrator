use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};


#[derive(Debug, Default)]
struct BinData {
    meta: Option<Value>,
    imports: Vec<Value>,
    exports: Vec<Value>,
    strings_typed: Vec<Value>,
    strings_raw: Vec<Value>,
    functions: Vec<Value>,

    // índices intra-binário
    addr_to_index: HashMap<String, usize>,
    name_to_entries: HashMap<String, Vec<String>>,
}

/// Lê um ficheiro NDJSON desta pasta e acumula em `data`.
fn process_ndjson_file(path: &Path, data: &mut BinData) -> std::io::Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let l = line?;
        if l.trim().is_empty() {
            continue;
        }

        let v: Value = match serde_json::from_str(&l) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Erro a parsear JSON em {:?}: {} -> {}", path, e, l);
                continue;
            }
        };

        let record_type = v
            .get("record_type")
            .and_then(|x| x.as_str())
            .unwrap_or("");

        match record_type {
            "binary_meta" => {
                // se houver mais do que um, fica o primeiro
                if data.meta.is_none() {
                    data.meta = Some(v);
                }
            }
            "import" => data.imports.push(v),
            "export" => data.exports.push(v),
            "string_typed" => data.strings_typed.push(v),
            "string_raw" => data.strings_raw.push(v),
            "function" => {
                // índice desta função no vetor
                let idx = data.functions.len();

                // extrair entry e name para índices
                let entry = v
                    .get("entry")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = v
                    .get("name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();

                if !entry.is_empty() {
                    data.addr_to_index.insert(entry.clone(), idx);
                }

                if !name.is_empty() {
                    data.name_to_entries
                        .entry(name)
                        .or_insert_with(Vec::new)
                        .push(entry);
                }

                data.functions.push(v);
            }
            _ => {
                // tipos desconhecidos: ignora
            }
        }
    }

    Ok(())
}

/// Processa uma pasta de binário (C:\ghidra_exports\<bin>) e gera export_full.json.
fn process_binary_folder(folder: &Path) -> std::io::Result<()> {
    let mut data = BinData::default();

    // ler todos os .ndjson desta pasta
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if let Some(ext) = p.extension() {
            if ext == "ndjson" {
                process_ndjson_file(&p, &mut data)?;
            }
        }
    }

    // construir objeto final
    let mut out_obj = serde_json::Map::new();

    // binary_meta (pode ser null se algo falhou no export)
    if let Some(meta) = data.meta.take() {
        out_obj.insert("binary_meta".to_string(), meta);
    } else {
        out_obj.insert("binary_meta".to_string(), Value::Null);
    }

    out_obj.insert("imports".to_string(), Value::Array(data.imports));
    out_obj.insert("exports".to_string(), Value::Array(data.exports));
    out_obj.insert("strings_typed".to_string(), Value::Array(data.strings_typed));
    out_obj.insert("strings_raw".to_string(), Value::Array(data.strings_raw));
    out_obj.insert("functions".to_string(), Value::Array(data.functions));

    // índices intra-binário
    let addr_map = data
        .addr_to_index
        .into_iter()
        .map(|(k, v)| (k, Value::from(v as u64)))
        .collect::<serde_json::Map<String, Value>>();
    out_obj.insert("addr_to_index".to_string(), Value::Object(addr_map));

    let mut name_map = serde_json::Map::new();
    for (name, entries) in data.name_to_entries.into_iter() {
        let arr = entries.into_iter().map(Value::from).collect::<Vec<_>>();
        name_map.insert(name, Value::Array(arr));
    }
    out_obj.insert("name_to_entries".to_string(), Value::Object(name_map));

    let out_path = folder.join("export_full.json");
    let out_file = File::create(&out_path)?;
    let mut writer = BufWriter::new(out_file);
    serde_json::to_writer_pretty(&mut writer, &Value::Object(out_obj))?;
    writer.flush()?;

    println!("Export full JSON: {:?}", out_path);
    Ok(())
}

/// Verifica se existe uma flag (ficheiro) na raiz out_root.
fn flag_exists(root: &Path, name: &str) -> bool {
    root.join(name).is_file()
}

fn main() -> std::io::Result<()> {
    // Uso:
    //   sc_export_builder <out_root>
    //
    // out_root = C:\ghidra_exports, por exemplo.
    //
    // Flags:
    //   C:\ghidra_exports\STOP_BUILD.flag  -> parar imediatamente
    //   C:\ghidra_exports\PAUSE_BUILD.flag -> parar limpo antes do próximo binário
    //
    // Resume:
    //   se C:\ghidra_exports\<bin>\export_full.json existir,
    //   essa pasta é ignorada (já processada).

    let out_root = std::env::args()
        .nth(1)
        .expect("Uso: sc_export_builder <out_root>");

    let root = PathBuf::from(out_root);

    if !root.is_dir() {
        eprintln!("Pasta não existe: {:?}", root);
        std::process::exit(1);
    }

    // obter lista de subpastas (cada subpasta = binário)
    let mut dirs: Vec<PathBuf> = fs::read_dir(&root)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();

    // ordem estável
    dirs.sort();

    for dir in dirs {
        // STOP_BUILD.flag -> termina imediatamente
        if flag_exists(&root, "STOP_BUILD.flag") {
            println!(
                "[STOP] STOP_BUILD.flag encontrado em {:?}, a terminar.",
                root
            );
            break;
        }

        // PAUSE_BUILD.flag -> termina antes de avançar para o próximo
        if flag_exists(&root, "PAUSE_BUILD.flag") {
            println!(
                "[PAUSE] PAUSE_BUILD.flag encontrado em {:?}, a pausar.",
                root
            );
            break;
        }

        // se export_full.json já existir, esta pasta está concluída
        let out_json = dir.join("export_full.json");
        if out_json.is_file() {
            println!("[SKIP] Já existe export_full.json em {:?}", dir);
            continue;
        }

        println!("[PROC] Pasta: {:?}", dir);
        if let Err(e) = process_binary_folder(&dir) {
            eprintln!("[ERRO] {:?}: {}", dir, e);
            // aqui continuo para as restantes; se quiseres que pare ao primeiro erro, troca por `break`
        }
    }

    println!("Builder terminado.");
    Ok(())
}
