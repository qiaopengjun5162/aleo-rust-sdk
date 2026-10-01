/// Cover: program from_file using from_local_file
#[test]
fn test_program_from_local_file_not_found_2() {
    let result = AleoProgram::from_local_file("/tmp/nonexistent_program_12345.aleo");
    assert!(result.is_err());
}

/// Cover: program from invalid file content
#[test]
fn test_program_from_file_invalid_source() {
    let path = std::env::temp_dir().join("invalid_program.aleo");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "not a valid program").unwrap();
    let result = AleoProgram::from_local_file(path.to_str().unwrap());
    assert!(result.is_err());
    let _ = std::fs::remove_file(&path);
}

/// Cover: program from_source with empty source
#[test]
fn test_program_from_source_empty() {
    let result = AleoProgram::from_source("");
    assert!(result.is_err());
}

/// Cover: program accessors
#[test]
fn test_program_accessors() {
    let prog = AleoProgram::from_source("program test.aleo;\nfunction main:\n    input r0 as u32.public;\n    output r0 as u32.public;\n").unwrap();
    assert_eq!(prog.id().to_string(), "test.aleo");
}

use aleo_rust_sdk::AleoProgram;
use std::io::Write;
