fn main() {
    let mut attributes = tauri_build::Attributes::new();
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.ends_with("windows-msvc") {
        // Embed the app manifest via the linker (/MANIFESTINPUT) instead of
        // tauri-winres resources. `tauri-winres` only applies to the final
        // bin/cdylib targets; unit-test binaries built from `--lib` get no
        // manifest, and dependencies (tao common-controls-v6) statically
        // import ComCtl32 v6-only symbols such as TaskDialogIndirect, which
        // crashed tests with STATUS_ENTRYPOINT_NOT_FOUND before they ran.
        // Cargo's scoped link-arg variants cannot express "lib unit tests
        // only", so the same manifest content is injected for every binary
        // target — the embedded result is identical to what tauri-winres
        // would have produced.
        let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("common-controls.manifest");
        println!("cargo::rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo::rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        attributes = attributes
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
    }
    if let Err(error) = tauri_build::try_build(attributes) {
        println!("{error:#}");
        std::process::exit(1);
    }
}
