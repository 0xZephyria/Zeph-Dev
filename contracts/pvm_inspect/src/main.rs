use polkavm_common::program::ProgramBlob;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "contracts/out/counter/Counter.elf".into());
    let data = std::fs::read(&path).expect("read file");
    println!("File: {} ({} bytes)", path, data.len());
    
    let blob = ProgramBlob::parse(data.into()).expect("parse PVM blob");
    
    println!("Code bytes: {}", blob.code().len());
    println!("Bitmask bytes: {}", blob.bitmask().len());
    println!("RO data: {} bytes", blob.ro_data().len());
    println!("RW data: {} bytes", blob.rw_data().len());
    
    println!("\nExports:");
    for exp in blob.exports() {
        let exp = exp.unwrap();
        println!("  '{}' -> PC={}", exp.symbol(), exp.program_counter().0);
    }
    
    println!("\nImports:");
    for imp in blob.imports() {
        let imp = imp.unwrap();
        println!("  #{}: '{}'", imp.index(), imp.symbol());
    }
    
    println!("\nFirst 30 code bytes (hex): {}", blob.code().iter().take(30).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
    println!("First 8 bitmask bytes (hex): {}", blob.bitmask().iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
}
