use anyhow::{anyhow, Result};
use std::fs;

use goblin::{
    Object,
    elf::Sym,
    elf64::reloc::{Rel, Rela},
};

// Import the trait and function from `plain` so we can parse bytes into Rel/Rela
use plain::{from_bytes};

fn main() -> Result<()> {
    let mut global_symbols = GlobalSymbolTable::new();

    // For example, we load b.o first, then a.o
    load_and_relocate_object("b.o", 0x20000, &mut global_symbols)?;
    load_and_relocate_object("a.o", 0x30000, &mut global_symbols)?;

    println!("\nDone loading both libraries!\n");

    println!("Global symbols known are:");
    for (name, sym) in &global_symbols.exports {
        println!(" - {} => address 0x{:x} (in file {})",
                 name, sym.address, sym.file_name);
    }

    Ok(())
}

/// Represents an exported symbol from one library file
struct ExportedSymbol {
    file_name: String,
    address: usize,
}

/// Holds a map of memory buffers keyed by file name,
/// plus a map of exported symbols by name.
struct GlobalSymbolTable {
    exports: std::collections::HashMap<String, ExportedSymbol>,
    mem_map: std::collections::HashMap<String, Vec<u8>>,
}

impl GlobalSymbolTable {
    fn new() -> Self {
        Self {
            exports: std::collections::HashMap::new(),
            mem_map: std::collections::HashMap::new(),
        }
    }
}

/// Load an ELF relocatable, place .text/.data in memory, parse relocations,
/// fill in or consume the global symbol table for cross-library references.
fn load_and_relocate_object(
    file_name: &str,
    load_base: usize,
    global_syms: &mut GlobalSymbolTable,
) -> Result<()> {

    println!("Loading file: {} at base 0x{:x}", file_name, load_base);

    // Read the object file
    let bytes = fs::read(file_name)?;

    // Parse the ELF
    let obj = match Object::parse(&bytes)? {
        Object::Elf(elf) => elf,
        _ => {
            println!("Not an ELF file: {}", file_name);
            return Ok(());
        }
    };

    // Create a memory buffer (512 KB, just as a toy example)
    let mut memory = vec![0u8; 512 * 1024];

    // Copy .text, .data, .rodata, etc. into 'memory'
    for sh in &obj.section_headers {
        if sh.sh_size == 0 {
            continue;
        }
        if let Some(name) = obj.shdr_strtab.get_at(sh.sh_name) {
            if name == ".text" || name == ".data" || name == ".rodata" {
                let section_start = load_base + (sh.sh_addr as usize);
                let section_end = section_start + (sh.sh_size as usize);

                let file_offset = sh.sh_offset as usize;
                let file_end = file_offset + (sh.sh_size as usize);

                memory[section_start..section_end]
                    .copy_from_slice(&bytes[file_offset..file_end]);

                println!("Copied section {}: 0x{:x}..0x{:x}",
                         name, section_start, section_end);
            }
        }
    }

    // Parse the symbol table and note which are exported vs. undefined
    let mut symbols: Vec<(String, Sym)> = Vec::new();
    let syms = &obj.syms;  // direct Symtab reference

    for sym in syms.iter() {
        if sym.st_name == 0 {
            continue;
        }
        if let Some(name) = obj.strtab.get_at(sym.st_name) {
            symbols.push((name.to_string(), sym));
        }
    }

    // For each symbol, if st_shndx != 0 => export
    for (sym_name, sym) in &symbols {
        if sym.st_shndx != 0 {
            let sym_addr = load_base + sym.st_value as usize;
            println!("Symbol '{}' exported at 0x{:x} by {}",
                     sym_name, sym_addr, file_name);

            global_syms.exports.insert(sym_name.clone(), ExportedSymbol {
                file_name: file_name.to_string(),
                address: sym_addr,
            });
        } else {
            // It's an undefined symbol => we'll patch references
            println!("Symbol '{}' is UNDEF in {}", sym_name, file_name);
        }
    }

    // Apply relocations: .rel.* (Rel) or .rela.* (Rela)
    apply_rel_or_rela(&obj, &bytes, false, load_base, &mut memory, &symbols, global_syms)?;
    apply_rel_or_rela(&obj, &bytes, true,  load_base, &mut memory, &symbols, global_syms)?;

    // Store the final memory buffer
    global_syms.mem_map.insert(file_name.to_string(), memory);

    Ok(())
}

/// Helper to parse .rel.* or .rela.* sections and apply them.
/// We use `plain::from_bytes::<Rel>` or `<Rela>` instead of `Rel::from_bytes`,
/// and we convert `plain::Error` into an `anyhow::Error` with `.map_err(...)`.
fn apply_rel_or_rela(
    obj: &goblin::elf::Elf,
    file_bytes: &[u8],
    is_rela: bool,
    load_base: usize,
    memory: &mut [u8],
    symbols: &[(String, goblin::elf::Sym)],
    global_syms: &mut GlobalSymbolTable,
) -> Result<()> {

    for sh in &obj.section_headers {
        if let Some(name) = obj.shdr_strtab.get_at(sh.sh_name) {
            if (is_rela && name.starts_with(".rela")) || (!is_rela && name.starts_with(".rel")) {
                println!("Processing relocation section: {}", name);

                let entry_size = if is_rela {
                    std::mem::size_of::<Rela>()
                } else {
                    std::mem::size_of::<Rel>()
                };
                let count = sh.sh_size as usize / entry_size;
                let mut offset = sh.sh_offset as usize;

                for _ in 0..count {
                    if is_rela {
                        let rela: Rela = *from_bytes::<Rela>(&file_bytes[offset..offset + entry_size])
                            .map_err(|e| anyhow!("Failed to parse Rela: {:?}", e))?;
                        offset += entry_size;

                        let sym_index = rela.r_info >> 32;
                        let r_type = (rela.r_info & 0xffffffff) as u32;
                        let reloc_offset = rela.r_offset as usize;
                        let addend = rela.r_addend;

                        apply_one_reloc(
                            reloc_offset,
                            sym_index as usize,
                            r_type,
                            addend,
                            load_base,
                            memory,
                            symbols,
                            global_syms
                        )?;
                    } else {
                        let rel: Rel = from_bytes::<Rel>(&file_bytes[offset..offset + entry_size])
                            .map_err(|e| anyhow!("Failed to parse Rel: {:?}", e))?.clone();
                        offset += entry_size;

                        let sym_index = rel.r_info >> 32;
                        let r_type = (rel.r_info & 0xffffffff) as u32;
                        let reloc_offset = rel.r_offset as usize;

                        // .rel typically has implicit addend = 0
                        apply_one_reloc(
                            reloc_offset,
                            sym_index as usize,
                            r_type,
                            0,
                            load_base,
                            memory,
                            symbols,
                            global_syms
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Actually patch the memory for one relocation
fn apply_one_reloc(
    reloc_offset: usize,
    sym_index: usize,
    r_type: u32,
    addend: i64,
    load_base: usize,
    memory: &mut [u8],
    symbols: &[(String, goblin::elf::Sym)],
    global_syms: &mut GlobalSymbolTable,
) -> Result<()> {

    let patch_addr = load_base + reloc_offset;

    println!("Applying reloc @ 0x{:x}, sym_idx {}, type {}, addend={}",
             patch_addr, sym_index, r_type, addend);

    // Find symbol name from sym_index
    let (sym_name, sym) = match symbols.get(sym_index) {
        Some(pair) => pair,
        None => {
            eprintln!("No symbol for index {}", sym_index);
            return Ok(()); // or bail!()
        }
    };

    // If st_shndx == 0 => it's an import => look up in global exports
    let final_addr: u64 = if sym.st_shndx == 0 {
        if let Some(export) = global_syms.exports.get(sym_name) {
            export.address as u64
        } else {
            eprintln!("Symbol '{}' not found in global exports!", sym_name);
            0
        }
    } else {
        // local definition => load_base + st_value
        (load_base + sym.st_value as usize) as u64
    };

    // Add the relocation addend
    let reloc_value = final_addr.wrapping_add(addend as u64);

    // Patch memory (8 bytes, little-endian)
    let bytes = reloc_value.to_le_bytes();
    for i in 0..8 {
        memory[patch_addr + i] = bytes[i];
    }

    println!(" -> Patched 0x{:x} with 0x{:x} (symbol={})",
             patch_addr, reloc_value, sym_name);

    Ok(())
}
