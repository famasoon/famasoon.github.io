---
title: "PEについてメモ"
date: "2023-07-21"
draft: "false"
---

# What is PE

PEファイルとはPortable Executable File Formatの略。

ポータブルな実行ファイルである。

## ビルド

たとえばtest.cppといったファイルを作成してビルドすると、まず関連するヘッダーとソースをコンパイルし1つの機械語コードを作成する。

この段階でReleaseディレクトリにobjファイルが生成される。

次にリンク作業が行われる。

リンカはOSでこのファイルを実行できるように動的ライブラリや様々なリソースデータ、インポート・エクスポートテーブルを処理するための情報をファイルに書き出す。

この際にWindowsは決まったルールに沿って情報を用意しExeファイルを作成する際に、ヘッダーに情報を書き込む。

これがPEフォーマットを作成する処理である。

PEヘッダーの中には実行ファイルを実行するために様々な情報が記録されている。

## PEファイルの構造

- IMAGE_DOS_HEADER
- IMAGE_NT_HEADER
- IMAGE_FILE_HEADER
- IMAGE_OPTIONAL_HEADER
- IMAGE_SECTION_HEADER
- IMAGE_IMPORT_DESCRIPTOR
- IMAGE_EXPORT_DIRECTORY
- IMAGE_IMPORT_BY_NAME
- IMAGE_THUNK_DATA32

主要な構造体は上記の通り。

### IMAGE_DOS_HEADER

```cpp
typedef struct _IMAGE_DOS_HEADER {       // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                   // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                         // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

`e_magic` , `e_lfanew` について注目するとよい。

`e_magic` はMZのあれである。

`e_lfanew` はIMAGE_NT_HEADERの位置を調べるために使用される値。

実際のPEのオフセットがどこにあるか調べるためにこのフィールドを使用する。

### IMAGE_NT_HEADER

```cpp
typedef struct _IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
```

`IMAGE_NT_HEADERS`は、`IMAGE_FILE_HEADER`と`IMAGE_OPTIONAL_HEADER`を含む構造体である。

`Signature`はPEファイルのシグネチャで、"PE\0\0"という4バイトの文字列である。

`FileHeader`は、PEファイルのファイルヘッダー情報を格納する構造体である。

`OptionalHeader`は、PEファイルのオプションヘッダー情報を格納する構造体である。

これらの構造体には、PEファイルの種類、リンクされたバイナリのアーキテクチャ、エントリーポイントなど、重要な情報が含まれる。

`Signature`は、PEファイルが有効なファイルかどうかを判断するために使用される。

`FileHeader`は、PEファイルのファイルヘッダー情報を格納する構造体である。

この構造体には、PEファイルの種類、リンクされたバイナリのアーキテクチャ、エントリーポイントなど、重要な情報が含まれる。

`OptionalHeader`は、PEファイルのオプションヘッダー情報を格納する構造体である。

この構造体には、PEファイルのセクションヘッダー、ディレクトリエントリ、エクスポート/インポートテーブル、リソーステーブル、リロケーションテーブル、エントリーポイントのアドレスなど、PEファイルの詳細な情報が含まれる。

また、`OptionalHeader`には、PEファイルの実行ファイルイメージに必要なクラス情報やセキュリティ情報が含まれる。たとえば、ビルド時に指定されたCPUアーキテクチャ、OSのバージョン、スタックサイズ、ヒープサイズ、デバッグ情報などが含まれる。

以上より、PEファイルの構造には、ファイルヘッダー、オプションヘッダー、セクションヘッダー、ディレクトリエントリ、エクスポート/インポートテーブル、リソーステーブル、リロケーションテーブルなど、様々な情報が含まれることがわかる。

### IMAGE_FILE_HEADER

この構造体はファイルを実行するために必要なデータが含まれている。

```cpp
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

MachineはどのCPUで実行できるか知ることができる。

NumberOfSectionsはセクションがいくつあるか知ることができる。

セクションは .text や .data といったコードセクションやデータセクションを指す。

通常は .text, .rdata, .data, .rsrc の4つのセクションが存在するため値は4になる。

もしパッキングや難読化がされている場合、セクションの数が変動するため、この値も変化する。

TimeDateStampはコンパイラによってobjファイルからexeが生成された時刻が格納されている。

ここを見ることでだいたいいつ頃作成されたか推測することができる。

とはいえ書き換えることもできるし、一部のコンパイラは特定の値を入れるようにしているため過信は禁物。

SizeOfOptionalHeaderはIMAGE_OPTIONAL_HEADER32の構造体の大きさ。

IMAGE_OPTIONAL_HEADER32はPEをロードするために必要な情報を含んでいるが、この構造体はOSごとにサイズが異なる場合があるためPEローダーではSizeOfOptionalHeaderを先に確認してからIMAGE_OPTIONAL_HEADER32を読み込む。

Characteristicsこのフィールドは現在のファイルがどのような形式か教えてくれる。

DLLかEXEかといった形で教えてくれる。

実際にはDLLかEXEか確認する方法は他にもあるのであまり注目しなくて良い。

## IMAGE_OPTIONANL_HEADER

```cpp
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

### Magic

32bitのときは0x10B, 64bitのときは0x20Bが入る

### SizeOfCode

コード全体のサイズを示す。

プログラマが作成したコードのサイズがどのくらいかこのフィールドに入る。

マルウェアはこのフィールドを参照して自分のコードを複製する場所の基準のポイントを作成する。

セキュリティソリューションではコードセクションの整合性チェックに使われる。

このセクションの値を参照してチェック対象のサイズを割り出すことができる。

### MajourLinkVersion, MinorLinkerVersion

どのコンパイラでビルドされたか入る。

### ImageBase

ファイルが実行される時に実際の仮想メモリにロードされるアドレスを示す。

exeファイルの場合、特定のアドレス指定オプションがない場合、このアドレスは0x400000になる。

PEファイルがメモリにマッピングされるアドレスと考えられる。

ただし、DLLの場合、基本的にImageBaseは0x10000000に指定されるが再配置される。

### AddressOfEntryPoint

実行ファイルがメモリ上で実行を開始するアドレス。

エントリポイント。

デバッガはこのアドレスで停止する。

exeの場合はWinMainCRTSetupになる。

dllの場合はDllMainCRTSetupになる。

アンパッキングするときにOEPを見つけなければならないが、それはこれである。

### BaseOfCode

実際のコードが実行されるアドレスと言える。

ImageBaseはPEファイルの開始アドレス。

コード領域が開始されるベースアドレスはImageBaseにBaseOfCodeを足した数値である。

特別なことがない限り、0x1000が指定される。

### SectionAlignment, FileAlignment

各セクションを整列するための保存単位。

通常は0x1000が指定されていて0x1000単位に分割する。

たとえば.textセクションとその次に.rdataセクションがあったとする。

.textの実際のサイズが0x800であれば800バイトの直後に.rdataが始まるわけではなく0x200バイトを0で埋める。

このように0x1000を全て満たしたあとに次のセクションになる。

セクションを配置するときの最小単位。

FileAlignmentはファイルの間隔、SectionAlignmentはメモリにロードされたときの間隔と考えれば良い。

### SizeOfImage

exe/dllがメモリにロードされたときの全体サイズである。

ローダーがPEをメモリにロードする時にSizeOfImageを見てこの分の領域を確保する。

ファイルの形で存在する場合とメモリにロードされた場合、大きさが同じになることもあるが、通常は異なる場合のほうが多い。

特にセクションの位置が重なる位置にマッピングされた場合はメモリにロードされたPEのサイズの方が大きい場合が多い。

前述のSectionAlignmentの倍数にになる。

例えばSectionAlignmentが0x1000であればSizeOfImageは0x8000, 0x9000となり0x8500のような値にはならない。

### SizeOfHeaders

PEヘッダーのサイズを示すフィールド。

0x1000であればメモリにロードされたときのアドレスの計算は容易になる。

(ImageBaseの0x10000000をそのまま加算するため)

だが0x400のような値になる場合もある。

この場合は計算をする必要があるためSizeOfHeadersので値を確認しなければいけないが面倒。SizeOfHeadersが0x1000であればこのPEファイルがファイルの形で存在する場合にも0x1000であり、メモリにロードされた時もそのまま0x1000になるので前述のようにファイルで見つけた値に0x400000などのImageBaseだけを加算すれば良い。

しかしSizeOfHeadersが0x400などのときはメモリ上のアドレスとファイル上のアドレスの0x400000を加算するだけでは済まない。

SizeOfHeadersが0x400になっている場合は直感的にアドレスを計算できず電卓等を使用して計算しないといけないので非常に面倒である。

### SubSystem

GUIかコンソール用か知らせる。

0x1: .sysなどのドライバーモジュール

0x2: GUIでウィンドウを持っているモジュール

0x3: コンソールアプリケーション

### DataDirectory

IMAGE_DATA_DIRECTORYの構造体でVirtualAddressとSizeという名前のフィールドが含まれている。

エクスポートテーブルまたはインポートディレクトリ、リソースディレクトリ、IATなどの仮想アドレスとサイズがこのフィールドでわかる。

```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

| オフセット (PE/PE32 以降) | 説明 |
| --- | --- |
| 96/112 | テーブルのアドレスとサイズをエクスポートする |
| 104/120 | テーブルのアドレスとサイズをインポートする |
| 112/128 | リソース テーブルのアドレスとサイズ |
| 120/136 | 例外テーブルのアドレスとサイズ |
| 128/144 | 証明書テーブルのアドレスとサイズ |
| 136/152 | ベース再配置テーブルのアドレスとサイズ |
| 144/160 | デバッグ情報の開始アドレスとサイズ |
| 152/168 | アーキテクチャ固有のデータ アドレスとサイズ |
| 160/176 | グローバル ポインター レジスタの相対仮想アドレス |
| 168/184 | スレッド ローカル ストレージ (TLS) テーブルのアドレスとサイズ |
| 176/192 | 構成テーブルのアドレスとサイズを読み込む |
| 184/200 | バインドされたインポート テーブルのアドレスとサイズ |
| 192/208 | アドレス テーブルのアドレスとサイズをインポートする |
| 200/216 | 遅延インポート記述子のアドレスとサイズ |
| 208/224 | CLR ヘッダーのアドレスとサイズ |
| 216/232 | 予約済み |

### RVA

RVAは Relative Virtual Addressの略。

相対アドレスのことを指す。

つまり絶対アドレスからベースアドレスを引いた値である。

実際のアドレスが0x403000でベースアドレスが0x400000であればRVAは0x3000である。

IATと呼ばれる項目のRVAが0x6000だとする。

またImageBaseを0x400000とする。

この場合IATのRVAが0x6000なのでファイルを実行しメモリにロードさせてから0x406000を見るとインポートされた関数の一覧が表示されるためIATが始まっていると言える。

## IMAGE_SECTION_HEADER

セクションヘッダーは各セクションの名前、開始アドレスとサイズについて管理する構造体。

```cpp
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

### IAT

直接アドレスを入力すると相対的なアドレス位置が変わった際に対応が非効率。

そこでインポートした関数のアドレスのテーブルを作成し、そのセクションで管理する。

これによりAPI呼び出しを行う箇所に応じてコードのセクションが変更されることはない。

これがIATの概念である。

## IATでAPIを計算する方法

まずはインポートの構造体であるIMAGE_IMPORT_DESCRIPTORについて書く。

```cpp
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    DWORD   TimeDateStamp;               // 0 if not bound,
    DWORD   ForwarderChain;               // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                      // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
```

読み込むDLLの数だけこの構造体が存在する。

NameにはDLLの名前が入る。

OriginalFirstThunkはこのDLLが持っている最初のアドレスになる。

この位置から4バイト単位で次のAPIのアドレスが入る。

各種APIの情報を入れる構造体はIMAGE_THUNK_DATA32である。

```cpp
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;
```

AddressOfDataはIMAGE_IMPORT_BY_NAMEを指す。

ここに各種APIの名前の文字列が入る。

```cpp
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    BYTE    Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

このようなAPIの配列をIATと呼ぶ。

IATはAPIのテーブルが保管されている位置でありexeやdllが実行される間、ここに集まっているAPIのアドレスを用いてインポートされた各DLLを呼び出す。

パックされたバイナリはインポート情報を壊すのでしっかりとアンパッキングしないとIATが壊れたままで実行されない。

したがってアンパッキングする際はインポートデータを回復する必要がある。

コンパイラのビルドによっては.idataでなく.rdataなどにIATが含まれたりする。

したがってすべてのセクションを探索してインポートデータを探す必要がある。

## エクスポートテーブル

インポートの内容とほぼ同じ。