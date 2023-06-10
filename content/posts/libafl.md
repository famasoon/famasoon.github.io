---
title: "[Note] LibAFLとはなにか"
date: "2023-06-10"
draft: "false"
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

## コンセプト

### Observer
テスト対象のぷろぐらむの実行を監視し、その情報をファザーに提供するものです。
これは `Observer` トレイトに書かれている。
各ファジングのデータを保持したりファジングケースの前後でフックしたりできる。

### Executor
テスト対処の実行に関する操作を定義するもの。
ファザー＝が実行で使用したい入力についてプログラムに通知し、特定のメモリの場所に書き込んだり、それをパラメータとしてハーネスに渡す責任がある。
`Executor` トレイとで提供されている。
`InprocessExecutor` はプロセス内のクラッシュを検出する。
`ForkserverExecutor` 子プロセスをファズするときに使う。

`InprocessExecotr` はファザープロセス内のハーネスを実行する。
ハーネスをできるだけ早く実行したいときはこれを採用する。
注意するべき点はハーネスにヒープ周りのバグがある可能性がある場合、クラッシュしたヒープがファザーに影響を与えないように別のアロケータを使用する必要があります。
例えばMiMallocを使用するなど。
あるいはアドレスサニタイザーを使用してハーネスをコンパイルしヒープ周りのバグを補足できるようにする。

`ForkserverExecutor` は共有メモリを使用してハーネスを実行する。

`InprocessForkExecutor` はハーネスを実行する前に分岐する。
ハーネスが不安定になったりクラッシュするような場合、子プロセスでハーネスを実行する必要がある。
そのような時に使用する。
ただしハーネスを実行し、カバレッジをマップに書くのは子プロセス。
親プロセスと子プロセスの間でマップを共有するために共有メモリを使用する。

### Feedback
フィードバックはテスト対象の実行結果が興味深いものかどうか判断するもの。
`Feedback` トレイトで定義されている。
フィードバックは1つ以上の `Observer` によって報告された情報を処理して興味深いかどうか判断する。
興味深さはエッジの新規性に関連している。

### Input
プログラムの入力は外部ソースから取得されたプログラムの動作に影響を与えるデータ。

### Corpus
コーパスはテストケースが保存される場所。
テストケースを入力として定義し、実行時間などの関連メタデータを合わせて定義する。
コーパスはディスク上やメモリでテストケースを保存したり、キャッシュを実装したりできる。
`Corpus` トレイトで定義されている。

### Mutator
1つ以上の入力を受取新しい入力を生成するもの。
`Mutator` トレイトで定義されている。

### Generator
入力を最初から生成するよう設計されたコンポーネント。
`Generator` トレイトで定義されている。

### Stage
コーパスから受け取った単一の入力で動作するもの。
コーパスの入力を指定するとミューテータを適用し入力を一回以上実行する。
何回実行するかスケジュールできる。
テストケースのトリミングとかで使えたりする。
