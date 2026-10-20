# MoonBit 0.10.16 on Windows

The tested release is `moonc v0.10.16+b1a0e846e`, with moon/moonrun `0.1.20261016 (1af328f)`.

This driver passes extended DOS paths (`\\?\C:\...`) to OCaml compiler/formatter tools which can fail with `Sys_error("\\\\?: Invalid argument")`. Using a previous build driver to bundle the newer core also produced a Wasm-GC link assertion. Both issues were reproduced independently of target trust decisions.

`tools/windows/path_shim.c` is an original small process adapter: it removes only the extended prefix on DOS drive-path arguments, quotes argv for CreateProcessW without a shell, and starts the installed official executable. It changes neither source nor output bytes. The wrapper temporarily sets the documented `MOONC_OVERRIDE`, `MOONFMT_OVERRIDE`, `MOONINFO_OVERRIDE` and `MOONDOC_OVERRIDE` process variables, then restores them. It never replaces installed compiler binaries. MSVC is required to build this optional host tool; generated executables stay in ignored `_build`.

```powershell
./tools/windows/build-shim.ps1
./tools/windows/moon.ps1 version --all
./tools/windows/moon.ps1 fmt --check
./tools/windows/moon.ps1 check --target all --deny-warn
./tools/windows/moon.ps1 test --target all --deny-warn
```

After a new 0.10.16 installation, rebundle the standard library with the new driver and path adapter, rather than mixing build-driver versions:

```powershell
$env:MOONC_OVERRIDE = (Resolve-Path './_build/windows-path-shims/moonc.exe').Path
Push-Location "$env:USERPROFILE/.moon/lib/core"
moon bundle --all --warn-list -a
Pop-Location
Remove-Item Env:MOONC_OVERRIDE
```

The CI Windows job performs these steps before ordinary `moon` gates. Linux uses ordinary official tools directly. Remove this workaround when an upstream Windows release fixes the path boundary; it is tooling adaptation, not a runtime dependency of the published MoonBit library.
