use aleo_rust_sdk::AleoProgram;
use std::io::Write;

/// Cover from_local_file (lines 17-21)
#[test]
fn test_program_from_local_file() {
    let dir = std::env::temp_dir();
    let path = dir.join("test_local_program.aleo");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "program test_local.aleo;").unwrap();
    writeln!(f, "function main:").unwrap();
    writeln!(f, "    input r0 as u32.public;").unwrap();
    writeln!(f, "    output r0 as u32.public;").unwrap();
    let prog = AleoProgram::from_local_file(path.to_str().unwrap()).unwrap();
    assert_eq!(prog.id().to_string(), "test_local.aleo");
    let _ = std::fs::remove_file(&path);
}

/// Cover inner() and into_inner() (lines 41-48)
#[test]
fn test_program_inner_accessors() {
    let prog = AleoProgram::credits().unwrap();
    let _inner = prog.inner();

    let prog2 = AleoProgram::credits().unwrap();
    let inner_owned = prog2.into_inner();
    assert!(inner_owned.id().to_string().contains("credits.aleo"));
}

/// Cover from_local_file error (missing file)
#[test]
fn test_program_from_local_file_not_found() {
    let r = AleoProgram::from_local_file("/tmp/nonexistent_xxxx.aleo");
    assert!(r.is_err());
}

/// Cover from_source with malformed
#[test]
fn test_program_from_source_malformed() {
    let r = AleoProgram::from_source("not a program");
    assert!(r.is_err());
}

/// Cover from_source happy path
#[test]
fn test_program_from_source_happy() {
    let src = "program test_happy.aleo;\nfunction main:\n    input r0 as u32.public;\n    output r0 as u32.public;\n";
    let prog = AleoProgram::from_source(src).unwrap();
    assert_eq!(prog.id().to_string(), "test_happy.aleo");
}
