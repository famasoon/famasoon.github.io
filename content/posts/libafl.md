---
title: "LibAFLとはなにか"
date: "2023-06-08"
draft: "true"
---

## LibAFL とは
[https://aflplus.plus/libafl-book/libafl.html](https://aflplus.plus/libafl-book/libafl.html)
ファジングのためのライブラリ。
AFL, libFuzzer, honggfuzz といったファザーは存在するが拡張性がない。
個々のソフトウェアに対してカスタマイズ可能なファザーを作るために開発された。

### 特徴
- マルチプラットフォーム対応
- OS依存のランタイムを必要としていない
 - なので組み込みデバイスやハイパーバイザ、WASMなどにつかえる(らしい)
- AFLPlusPlusで培った経験が活かされている
- スケールしやすいらしい
- 早い
- ソフトウェアに合わせてカスタムできる

## 入門
`crate` として使える。
注意点としてClangに依存しているので予めインストールする必要がある。

各種プロジェクトのルートディレクトリから `cargo build --release` を実行することでビルドできる。
下記のように `Cargo.toml` に書けば良い(私は `cargo add` で入れた)

```toml
[dependencies]
libafl = { version = "*" }
```

色々とカスタムできるがクレートとしては `libafl` を使えば良さそう。
他のクレートの説明はこちら。
https://aflplus.plus/libafl-book/getting_started/crates.html

## 使ってみる
まずはシンプルな内容で作ってみる。

```sh
cargo new baby_fuzzer
cd baby_fuzzer
```