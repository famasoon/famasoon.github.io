---
title: "Anti-debug introduction"
date: "2023-10-12"
draft: "false"
---

# Anti-debug

アンチデバッグのやり方はたくさんあるが、その中でもよく使われるものを紹介する。

網羅的に把握したい場合は下記リンクを参照すると良い。

https://unprotect.it/category/anti-debugging/

## 古典的なアンチデバッグ

```cpp
bool FindDebugger() {
  bool bDetect = false;
  HWND hDebugger = ::FindWindow(NULL, "OllyDBG");
  if (hDebugger) {
    bDetect = true;
    AfxMessageBox("Can not use debugger");
  }
  return bDetect;
}
```

デバッガーのウィンドウキャプションを見つけてプログラムを終了させる。

## IsDebuggerPresent

MSDNに記載されていてkernel32.dllから提供されている。

```cpp
if (IsDebuggerPresent()) {
  exit(1);
}
```

アセンブリになると下記のようになる

```cpp
mov eax, dword ptf fs:[18]
mov eax, dword ptr ds:[eax+30]
movzx eax, byte ptr ds:[eax+2]
retn
```

fs:[18] はTEBを指す。(Thread Environment Block)

TEBをEAXに入れたがそこから30番地離れたアドレスを再びEAXに入力するコードだ。

TEBから0x30離れたところにはPEB(Process Environment Block) がある。

EAXにはPEBが入っていて、そこから+2移動したアドレスから1バイト持ってきていると解釈できる。

PEBの構造体は下記の通り。

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

`BeingDebugged` という名前の箇所の値を入れている。

ここにtrueが入っているとデバッグ中であり、falseが入っているとデバッグ中ではないことを表現する。

## NtQueryInformationProcess

ntdll.dllにエクスポートされている `NtQueryInformationProcess()` というネイティブAPIを利用した方法を書く。

デバッグポートをチェックする方法と呼ばれる。

デバッグポートはカーネルで管理する `EPROCESS` 構造体の `DebugPort` フラグで有効にされ、 `NtQueryInformationProcess` はその値を取得する。

`NtQueryInformationProcess` の2番目の引数として7を渡すとデバッグポートがチェックされる。

`CheckRemoteDebuggerPresent` という関数でも提供され `kernel32.dll` にエクスポートされている。

チェックを実装するコードも簡単である。

```cpp
BOOL bDebugged = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugged);
if (bDebugged) exit(1);
```

内部的にはNtQueryInformationProcessを使用する。

## Debug Object Handle

`NtQueryInformationProcess()` はアンチでバッグに関連して多くの機能を提供する。

デバッグポートに加えてデバッグ時に使用されるDebug Object Handle というハンドルを取得してくれる。

2番目の引数に0x1Eという値を入れると、3番目の引数にハンドルのポインターを渡してくれる。

このハンドルの有効性を確認するとデバッグ中かどうか確認できる。

## NtQUeryObject

前述したDebug Object Handle を検索する方法と同様に `NtQueryObject` というネイティブAPIを呼び出す方法もある。

これはシステムで現在デバッガーが動作中である場合にどんな変化があるか調べる方法である。

デバッグ中はカーネル内にDebugObject型のオブジェクトが生成されるが `NtQueryObject()` を呼び出すとすべてのオブジェクトの型の情報が手に入るのでここでDebugObjectのオブジェクトも取得して確認する。

`NtQueryObject` では2番目の引数にどのようなオブジェクトを取得するか指定する。ここではすべてのオブジェクトの情報を取得する必要があるので `ObjectAllInformation` である3を指定する。

そして取得したオブジェクトの中から `DebugObject` というオブジェクトを文字列比較で探し、その文字列が存在したらシステムには現在でバッグオブジェクトが存在し、デバッグ中であることがわかる。

## NoDebugInherit

`NtQueryInformationProcess()` にはもう一つのデバッグチェック機能がある。

0x1fを2番目の引数に渡すとProcessDebugFlagsとなり、デバッグ中であることを判断してくれる。

2番目の引数に0x1fを2番目の引数に渡すと3番目の引数にNoDebugInheritが渡される。

## NtSetInformationThread

スレッドをデバッガーから隠す方法。

使用する引数の名前も `ThreadHideFromDebugger` でわかりやすい。名前にHideという名前が入っているが完全にスレッドが隠れるわけではない。

デバッガーがスレッドを呼び出す際に制御を譲ってくれないだけである。

```cpp
NTSYSAPI NTSTATUS ZwSetInformationThread(
  [in] HANDLE          ThreadHandle,
  [in] THREADINFOCLASS ThreadInformationClass,
  [in] PVOID           ThreadInformation,
  [in] ULONG           ThreadInformationLength
);
```

この関数の本来の役割はスレッドの優先順位を設定することだが、Windows 2000からは純粋にアンチデバッグのためにこの関数をアップグレードしたと言われる。

重要なのは `THREAD_INFORMATION_CLASS` の enum 値である。

0x11の値にThreadHideFromDebuggerという名前がある。

これを引数として渡すと生成したスレッドをデバッガーから隠すことができる。

| Numeric Value | Symbolic Name | Versions |
| --- | --- | --- |
| 0x00 | ThreadBasicInformation | all |
| 0x01 | ThreadTimes | all |
| 0x02 | ThreadPriority | all |
| 0x03 | ThreadBasePriority | all |
| 0x04 | ThreadAffinityMask | all |
| 0x05 | ThreadImpersonationToken | all |
| 0x06 | ThreadDescriptorTableEntry | all |
| 0x07 | ThreadEnableAlignmentFaultFixup | all |
| 0x08 | ThreadEventPair | 3.10 to 4.0 |
|  | ThreadEventPair_Reusable | 5.0 and higher |
| 0x09 | ThreadQuerySetWin32StartAddress | all |
| 0x0A | unknown | 3.10 only |
| 0x0B (3.10);0x0A | ThreadZeroTlsCell | all |
| 0x0B | ThreadPerformanceCount | 3.51 and higher |
| 0x0C | ThreadAmILastThread | 3.51 and higher |
| 0x0D | ThreadIdealProcessor | 4.0 and higher |
| 0x0E | ThreadPriorityBoost | 4.0 and higher |
| 0x0F | ThreadSetTlsArrayAddress | 4.0 and higher |
| 0x10 | ThreadIsIoPending | 5.0 and higher |
| 0x11 | ThreadHideFromDebugger | 5.0 and higher |
| 0x12 | ThreadBreakOnTermination | 5.2 and higher |
| 0x13 | ThreadSwitchLegacyState | 5.2 from Windows Server 2003 SP1, and higher |
| 0x14 | ThreadIsTerminated | 5.2 from Windows Server 2003 SP1, and higher |
| 0x15 | ThreadLastSystemCall | 6.0 and higher |
| 0x16 | ThreadIoPriority | 6.0 and higher |
| 0x17 | ThreadCycleTime | 6.0 and higher |
| 0x18 | ThreadPagePriority | 6.0 and higher |
| 0x19 | ThreadActualBasePriority | 6.0 and higher |
| 0x1A | ThreadTebInformation | 6.0 and higher |
| 0x1B | ThreadCSwitchMon | 6.0 and higher |
| 0x1C | ThreadCSwitchPmu | 6.1 and higher |
| 0x1D | ThreadWow64Context | 6.1 and higher |
| 0x1E | ThreadGroupInformation | 6.1 and higher |
| 0x1F | ThreadUmsInformation | 6.1 and higher |
| 0x20 | ThreadCounterProfiling | 6.1 and higher |
| 0x21 | ThreadIdealProcessorEx | 6.1 and higher |
| 0x22 | ThreadCpuAccountingInformation | 6.2 and higher |
| 0x23 | ThreadSuspendCount | 6.3 and higher |
| 0x24 | ThreadHeterogeneousCpuPolicy | 10.0 and higher |
| 0x25 | ThreadContainerId | 10.0 and higher |
| 0x26 | ThreadNameInformation | 10.0 and higher |
| 0x27 | ThreadSelectedCpuSets | 10.0 and higher |
| 0x28 | ThreadSystemThreadInformation | 10.0 and higher |
| 0x29 | ThreadActualGroupAffinity | 10.0 and higher |
|  | MaxThreadInfoClass | all |

## int 3の利用

デバッガーは `int 3` や `int 1` 命令を通過するとき基本的に例外処理をしない。

したがってデバッガーでは `__except`コードを実行しないためデバッグ中かそれで判断できる。

```cpp
void Int3SingStepDetection() {
  DWORD dwDebugger = 1;
  __try {
    __asm {
      __emit 0xcc
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER) {
    dwDebugger = 0;
  }
  if (dwDebugger) exit(1);
}
```

デバッガを使用中でなければこのコードは__try 野中を実行してint 3 を呼び出す。

int 3 が呼ばれると例外になり __exceptが実行され dwDebuggerが0になる。

しかしデバッガーの使用中だと例外が発生した際に __except内は実行されず例外処理をデバッガーに引き渡すので dwDebuggerが0にならない。

そのためデバッガーを使用していることがわかる。

`__emit 0xcc` は `int 3` を記録したコードである。

この方法はシングルステップで進むときにのみ検出され `int 3` を強制的に呼び出すコードの部分を jmp に飛ばしてしまうと検出されないという欠点がある。

また OllyDBGのオプションの追加で簡単に回避できたりする。

パッカーが自身のコードを複合するために使用したりする。

## SetUnhandledExceptionFilter

同様の技術で `SetUnhandeledExceptionFilter` を利用した方法もある。

Windows XP以降のシステムでは例外処理についてSEH(Structured Exception Handling)を使用せずにベクトル化例外処理であるVEH(Vector Exception Handling)を使用する。

したがってプログラミングをするとき次のような構造となる。

```cpp
void main() {
  SetUnhandledExceptionFilter(OnMyException);
}

LONG WINAPI OnMyException(PEXCEPTION_POINTERS pExcepPointers){
 //例外処理
}
```

この技術では例外が起きるとプログラマが作成したOnMyException()という例外処理関数が呼び出されそのハンドラの中で例外を処理する。

今度はEIPを直接コントロールしながら例外が発生したときとそうでないときのコードの流れを変更する。

```cpp
void UnHandleException() {
  SetUnHandleExceptionFilter(UnhandledExceptionFilter);
  __asm{xor eax, eax}
  __asm{div eax}
}
```

このようにSetUnhandledExceptionFilter APIを利用して例外が発生したときにUnhandledExcepFilterが呼び出されるようにした。そして次の行ですぐにEAXを0いし、それを割り算するコードを続け例外が発生するコードを作成した。

例外が起きると次のコードが実行される。

```cpp
LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers){
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)pExcepPointers->ContextRecord->Eax);
  pExcepPointers->ContextRecord->Eip += 2;
  return EXCEPTION_CONTINUE_EXECUTION;
}
```

EXCEPTION_POINTERS構造体を使用することができるのでContextの値をコントロールすることが可能である。

EIPを取得して現在のEIPの位置を2だけ増加させてから次の処理を実行するように記述した。

EIPは現在事項されているコードのアドレスが入っているレジスタである。

それを2だけ増やしたということはポインターを2だけ増加させたことになる。

例外が発生している状態ではEIPは例外が発生した場所になる。

するとポインターが移動しretnに飛ばされる。

つまり例外が発生したコードをスキップしその次の正常なコードに移動させるコードとなる。

最初の__tryを用いた手法よりも若干高度になった。

あとは__tryを用いたときと同様に書けばデバッグを回避することができる。

## 0xCCそのものを検出する

int 3の値である0xCCについて深堀する。

ユーザレベルのデバッガを使用するとブレークポイントを必ず設定することになる。

ブレークポイントは割り込み3番でオペコードは0xCCになる。

このためデバッグ中の場合は必ず現在のEIPに0xccが入るのでそれをチェックする方法もある。

0xCCが入るとコード領域の部分のハッシュ値が変更されるのでハッシュ値を検査する方法でもデバッグ中か判断できる。

## PEBを利用した方法

プロセス内部のフラグ情報を利用して現在のプログラムがデバッグ中華判断する方法。

PEBにはプロセスオブジェクトのいくつかの情報が入っている。

代表的なものとしてイメージベースアドレス、ヒープマネージャ、DLL関連の情報などがはいっている。

デバッグ関連情報もこの構造体を通じて確認可能。

PEB構造体にアクセスするといくつかのメンバー変数の値を用いて現在のプログラムがデバッグ中かどうか判断できる。

PEBはユーザプロセス空間に入っているがFSレジスタを利用して簡単に求めることができる。

デバッグの検出方法はBeingDebuggedメンバー変数を取得する方法である。

```cpp
mov eax, fs:[30h]
mov eax, byte[eax+2]
test eax, eax
jne @DebuggerDetected
```

fs:[30h] がPEBでありその0x2番目のメンバがBeingDebuggedである。

IsDebuggerPresentと同じ内容。

次はPEBの0x68番目のメンバ変数である `NtGlobalFlag` を利用する方法である。

プロセスが生成されたあと、システムでは各プロセスに対していくつかフラグを設定するがNtGlobalFlagの場合にはデバッグ中でない場合は0、デバッグ中の場合は0x70という値が設定される。

```cpp
mov eax, fs:[30h]
mov eax, [eax+68h]
and eax, 0x70
test eax, eax
jne @DebuggerDetected
```

上記コードで検知できる。

3番目はヒープフラグを使用した方法である。

仕組みはBeingDebuggedやNtGlobalFlagと同様である。

PEBにアクセスしたあとProcessHeapに対応する構造体のアドレスを取得し、その値を比較してデバッグ中であるか確認する。

ProcessHeapはHANDLE型なのでHEAP構造体にもう一度アクセスしなければならない。

プロセスのヒープが生成されるとき0xcと0x10の位置にFlags, ForceFlagsのメンバがあることがわかる。また、それぞれ2,0の値が入る。

しかしデバッグ中はそれぞれ0x50000062と0x40000060に変わる。

この規則性を利用して確認すればデバッグ中か確認できる。

Flagsの場合

```cpp
mov eax, fs:[30h]
mov eax, [eax+18h]; process heap
cmp dword [eax+0x0c], 2
jne .debugger_found
```

ForceFlagsの場合

```cpp
mov eax, [eax+10h]; force flags
test eax, eax
jne @DebuggerDetected
```

## プロセスのチェック

プロセスを列挙する。

Process32First/Process32Nextを用いることでデバッガのプロセスを見つけることができる。

## バージョンチェック

現在実行中のプロセスのバージョン情報を取得しそれがデバッガなどの値と一致すればデバッグ中であると判断できる。

OllyDBGなどではアンチでバッグを避けるためにファイルをパッキングしたりウィンドウの文字列を変更したり実行ファイル名を変更することはあるがバージョン情報を書き換えることは少ない。

バージョン情報は `VerQueryValue` というAPIを呼び出すことでバージョンを調べることができる。

## 親プロセスのチェック

プロセスを実行させた主体がどのプロセス化チェックする方法。

システムで実行されるプロセスはそのプロセスを実行させた親プロセスが存在する。

たとえばエクスプローラからメモ帳を起動すると子プロセスのnotepad.exeの親プロセスはexplorer.exeになる。

`ToolHelp32` ライブラリを利用すると `PROCESSENTRY32` という構造体の中に `th32ParentProcessID`  という名前の変数がある。

この変数の中に親プロセスのPIDが含まれているので親プロセスのPIDが explorer.exeやcmd.exe出ない場合はデバッグ中だと判断できる。

## SeDebugPrivilege 権限チェック

プロセスのデバッグ中はSeDebugPrivilege権限を使用することになる。

したがってSeDebugPrivilege権限を得た場合、システムプロセスの一つである csrss.exe のプロセスのハンドルが取得できるのでこれを取得できるかどうかに着目した方法をアンチでバッグに利用できる。

csrss.exeのプロセスをOpenProcess()で開いてハンドルが取得できたら現在のプロセスはSeDebugPrivilege権限を得ていると仮定し、デバッガーによって実行されていると判断できる。

Tool Help LibraryでProcess32Nextでループを回って取得しても良いが、ntdll.dllにはCsrGetProcessIdというAPIがある。この関数を用いるとcsrss.exeのPIDを取得する。

これをOpenPorcess関数の引数として私PROCESS_ALL_ACCESS権限でプロセスハンドルを取得できればデバッグされていると判断できる。

## WINDBGの検出

```cpp
bool WindbgClassNameDetect() {
  HANDLE hWinDbg = ::FindWindow("WinDbgFrameClass", NULL);
  if (hWinDbg) return true;
  return false;
}
```

WinDBGはWinDbgFrameClassというクラス名を持っているのでそのクラス名でハンドルを見つけることで検出可能である。

## キーボード入力のブロック

リバースエンジニアリング、デバッグ時にキーボードやマウスの操作をできなくする。

BlockInput() というWin32 APIがその役割を果たす。引数にTRUEを渡すとキーボードやマウス入力がブロックされ、FALSEを渡して再び呼び出すと入力が可能になる。

```cpp
void BlockAllControl() {
  typedef BOOL (__stdcall *TBLOCKINPUT)(BOOL);
  TBLOCKINPUT fnBlockInput = (TBLOCKINPUT)GetProcAddress(GetModuleHandle("user32.dll"), "BlockInput");
  fnBlockInput(TRUE);
  sleep(5000);
  fnBlockInput(FALSE);
}
```

5秒間マウスとキーボードの動きを止めるサンプル。

## 時間差攻撃

```cpp
DWORD TimeCheck(int a, int b){
  DWORD dwStart = GetTickCount();
  int c = a ^ 0x369;
  int d = c + b * 0xdead;
  int e = d / a;
  DWORD dwEnd = GetTickCount();
  if (dwEnd - dwStart > 1000)
    return e = 0;
  return e;
}
```

リバースエンジニアリングしているときは1秒以上実行に時間がかかるはずなのでデバッグ中であると判断できる。

rdtscを利用した方法はWinAPIを使用しないので比較的強力である。

## PREFIX REP による例外処理

例外ハンドラに送るものと似たような方法。

インラインアセンブラでprefix値を追加するとデバッグ中とそうでないときで実行のされ方が異なることを利用した方法。

```cpp
bool IsDbgPresentPrefixCheck() {
  __try {
    __asm __emit 0xF3
    __asm __emit 0x64
    __asm __emit 0xF1
  }
  __except(EXCEPTION_EXECUTE_HANDLER) {
    // debugger not found
    return false;
  }
  return true;
}
```

__asm 似続けて __emit を入力してからオペコードを入れると0xF3という値がバイナリにそのまま埋め込まれる。すなわちこのコードのようにアセンブラコードを3業入れるとバイナリには次のように記録される。

```cpp
F3 64 // prefix rep
F1  // int 1
```

prefix rep命令は本来はリピートの用途で使用されるが、この命令を上記のように作成しておいてしうぐにint 1を呼び出すとデバッグ中には正常に動作しない。

通常の状況であれば次のステップに進みint 1で例外ハンドラに移るのだが、現在のプログラムがデバッグ中である場合はハンドラに進まず return true;に進むのでデバッグ中だと判断することができる。

コードがこのように動く理由は pop ss が実行されると CPU はスタックが壊れないように割り込み発生を防ぐからである。

このためシングルステップトレースでフラグを設定しても無視されて結局デバッガでは実行されてしまい検出できなくなる。

アセンブラコードの影響で少し複雑に見えるが例外ハンドラを利用した分岐の延長だと思えば簡単だ。

## API フックを利用したデバッグ検出

APIフックを利用してアンチでバッグ機能を実現することができる。

デバッガをプイロセスにあタッチする際、内部的にDebugActiveProcess() というAPIを利用する。

このAPIを無力化するとアタッチ自体が不可能になるためデバッグとリバーシングが困難になる。

```cpp
BOOL DebugActiveProcess(DWORD dwProcessId)
```

BOOL 変数であるためこのAPIをブロックするにはFALSEを返すだけで良い。

戻りちはEAXに入るため、EAXに値を入れてリターンさせるコードをDebugActiveProcess()のエントリポイントに入力しよう。

DbgUiRemoteBreakinやOpenProcess, ReadProcessMemory, WriteProcessMemoryを無力化してデバッガでプロセスの情報を得られないようにすることができる。

DbgUiRemoteBreakinカーネルではKiMoveApcState, KeStackAttachProcessなどのAPIを制御してプロセスのあタッチをより低いレベルで管理することができる。

## リモートでバッグの検出

```cpp
BOOL IsRemoteDebugger() {
  BOOL bDetection = FALSE;
  KdRefreshDebuggerNotPresent();
  if (KD_DEBUGGER_NOT_PRESENT == FALSE) {
    bDetection = TRUE;
    DbgPrint("Debugger attached");
  } else {
    DbgPrint("Debugger Not Attached");
  }
  return bDetection;
}
```