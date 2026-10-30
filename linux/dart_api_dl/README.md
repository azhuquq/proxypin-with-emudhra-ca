# dart_api_dl — vendored Dart Dynamic API shim

Vendored verbatim from `dart-sys` 4.1.5 (`dart-sdk/include/`, itself mirroring
the Dart SDK headers; Dart headers are BSD-3-Clause, the crate is MIT/Apache-2.0)
to match the `flutter_rust_bridge` 2.12 vendored by the `code_forge` plugin.

## Why this lives in the runner

`code_forge`'s Rust crate (via `dart-sys`) references the Dart Dynamic API
symbols (`Dart_CurrentIsolate_DL`, `Dart_InitializeApiDL`, ...). Whether
`libcode_forge.so` ends up with these symbols *defined* (static archive
`dart_api_dl.c` linked in) or left *undefined* depends on the cargo/linker
environment of the build machine; the plugin is a transitive dependency, so
cargo sometimes drops dart-sys' `rustc-link-lib` directives. The Flutter
Linux embedder, unlike the Android/Windows engines, exports no `Dart_*`
symbols at all (release, profile and debug artifacts only export `fl_*`).

When `libcode_forge.so` comes out with undefined `Dart_*` symbols **and**
`DT_BIND_NOW` (set by distro hardening flags, e.g. Arch's `-z now`),
`DynamicLibrary.open()` fails at load with
`undefined symbol: Dart_CurrentIsolate_DL`, `RustLib.init()` never runs and
every code_forge editor renders as a blank gray ErrorWidget.

Compiling `dart_api_dl.c` into the runner and exporting its symbols makes the
plugin loadable in both variants, independent of the build environment:

- good build of the plugin: fully self-contained, runner copy unused;
- broken build: its references bind to the runner's slots, and frb's init
  (`Dart_InitializeApiDL(NativeApi.initializeApiDLData)`) fills them.

Do not edit these files by hand; they mirror dart-sys' copies of the Dart SDK
headers so the `DART_API_DL_MAJOR_VERSION` handshake stays consistent with
flutter_rust_bridge 2.12 / dart-sys 4.1.5.
