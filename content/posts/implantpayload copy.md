---
title: "Connect to Ldap3 with Rust"
date: "2023-06-01"
draft: "false"
---

## What is Ldap
LDAP stands for Lightweight Directory Access Protocol. It is an open and platform-independent protocol used for accessing and maintaining directory services over a network. Directory services store and organize information, such as user names, passwords, email addresses, and other attributes, in a hierarchical structure.

LDAP is commonly used in client-server applications and network environments to facilitate centralized management of user authentication, authorization, and directory information. It allows clients to search, modify, and retrieve data from a directory server, which stores the directory information.

Key features of LDAP include:

Lightweight: LDAP is designed to be simple and efficient, making it suitable for use in resource-constrained environments.

Directory structure: LDAP organizes data in a hierarchical structure called the Directory Information Tree (DIT). The DIT consists of entries that represent objects, such as users, groups, and devices. Each entry has a unique identifier called a Distinguished Name (DN).

Protocol operations: LDAP defines a set of operations that clients can use to interact with the directory server. These operations include searching for entries, adding new entries, modifying existing entries, and deleting entries.

Security: LDAP supports authentication and data encryption mechanisms to ensure secure communication between clients and servers. It can integrate with various authentication methods, such as username/password, Kerberos, and SSL/TLS.

LDAP has widespread usage in various domains, including network authentication, email systems, centralized user management, and organizational directories. It is commonly employed in enterprise environments to enable centralized authentication and directory services for applications, services, and network resources.

## Connect with Rust
In this case, use `ldap3` package.

```
use ldap3::*;

fn main() {
    let ldap = LdapConn::new("ldap://192.168.0.100:3268");
    let mut ldap_con = match ldap {
        Ok(l) => l,
        Err(e) => panic!("{}", e),
    };

    ldap_con
        .simple_bind("CN=Administrator,CN=Users,DC=famasoon,DC=local", "password")
        .unwrap();
    let res = ldap_con
        .search(
            "DC=famasoon,DC=local",
            Scope::Subtree,
            "(objectclass=user)",
            vec!["dn"],
        )
        .unwrap();
    let (re, _ldap_result) = res.success().unwrap();
    for i in re {
        println!("{:#?}", SearchEntry::construct(i).dn);
    }
}
```