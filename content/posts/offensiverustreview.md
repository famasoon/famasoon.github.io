---
title: "Offensive Rustのレビュー"
date: "2023-10-11"
draft: "false"
---
# Offensive Rust

かんたんなまとめ: Rustでレッドチームシミュレータを書きたい人におすすめ。

## リンク

[https://redteamsorcery.teachable.com/courses/enrolled/1973492](https://redteamsorcery.teachable.com/courses/enrolled/1973492)

[https://www.udemy.com/course/offensive-rust/](https://www.udemy.com/course/offensive-rust/)

アフィリエイトはないです。

## 概要

本教材ではオフェンシブなコード、レッドチーム向けのコードをRustで書いていく。

なお、対象環境はWindows。

WSLとかではなくWindowsに直接Rustをインストールする。

## 内容

内容はかなり多岐にわたる。

最初の方ではRustのセットアップを実施し、基礎的なRustの書き方を教えてくれる。

中盤からはオフェンシブなコードを書いていく。

例えばLDAPを用いたActive Directoryの列挙であったり、シェルコードを書いたり、DLLインジェクションを行ったりと、基本的なRustの書き方を抑えつつレッドチーム向けのコードを書いていく。

また、Reflective PE Loaderを書いたり、Process Hollowingをやったり、ハッシュ化した関数呼び出しをしたりとレッドチームシミュレータで実行しそうな内容をRustでどのように書くか教えてくれる。

以降もAMSIのバイパスの仕方やProcess Doppelgangingの仕方をRustで解説してくれる。

総じてレッドチームシミュレータをRustで書いてみたいと方にはおすすめの内容。

各パートは体感ではそこまで長くなく、サッと書いてサッと試すということをやっていく。

## まとめ

レッドチーム向けのシミュレータを書きたいとなったとき、候補としてはC/C++が挙がるがRustで書きたい人は、この教材を買って見てみると良いだろう。