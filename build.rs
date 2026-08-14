fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    // Static imports resolve before main can install the process-wide dynamic-library policy.
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;
    println!("cargo::rustc-link-arg-bins=/DEPENDENTLOADFLAG:{LOAD_LIBRARY_SEARCH_SYSTEM32:#x}");
}
