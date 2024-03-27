extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut config = cbindgen::Config::default();
    config.autogen_warning =
        Some("/* WARNING: this file was auto-generated by cbindgen. do not modify. */".into());
    config.tab_width = 4;

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_cpp_compat(false)
        .generate()
        .expect("cbindgen unable to generate C bindings")
        .write_to_file("kateth.h");
}
