use std::{env, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let target = args.next().ok_or("usage: replay TARGET FILE...")?;
    let files: Vec<_> = args.collect();
    if files.is_empty() {
        return Err("usage: replay TARGET FILE...".into());
    }
    for file in files {
        eprintln!("replaying {target}: {file}");
        libmkiso_fuzz::run(&target, &fs::read(file)?)?;
    }
    Ok(())
}
