---
title: "LibFuzzerを使った"
date: "2023-07-04"
draft: "false"
---

## LibFuzzerを使った
https://x64.moe/posts/whatslibfuzzer/
こんな感じにファジングできるLibFuzzerを使ってみた。
結論としてはどれもうまくいかなかった(クラッシュしない・クラッシュしても配布されるビルドのものだとクラッシュしない等など)

## ターゲット
### Jansson
https://github.com/akheron/jansson
なんかのパーサがやりやすいかなと思ってJSONパーサのJanssonを選んだ。

```cpp
#include <stddef.h>
#include <stdint.h>

#include "jansson.h"

int parseJson(const char *buffer, size_t buflen) {
  json_error_t error;
  json_t *root;
  json_t *obj;
  const char *str;
  double dValue;
  int iValue;

  root = json_loadb(buffer, buflen, 0, &error);

  if (root == NULL) {
    return 0;
  }

  obj = json_object_get(root, "dateTime");

  if (json_is_string(obj)) {
    str = json_string_value(obj);
  }

  obj = json_object_get(root, "eventType");

  if (json_is_string(obj)) {
    str = json_string_value(obj);
  }

  obj = json_object_get(root, "DependOnSequentialEvent");

  if (json_is_object(obj)) {
    json_t *obj2;
    obj2 = json_object_get(obj, "valPercent");
    if (json_is_real(obj2)) {
      dValue = json_real_value(obj2);
    }
    else if (json_is_integer(obj2)) {
      iValue = json_integer_value(obj2);
    }
    obj2 = json_object_get(obj, "alive");
    if (json_is_string(obj2)) {
      str = json_string_value(obj2);
    }
    obj2 = json_object_get(obj, "isScript");
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 0) {
    return -1;
  }
  parseJson((const char *)data, size);
  return 0;
}
```

ビルド内容は下記のような感じ
クラッシュしなかった。

### libmxml
https://github.com/michaelrsweet/mxml
今度はXMLパーサのlibmxmlを選んだ。
この時もパーサなら行けるだろうと思っていた。

```cpp
#include <stddef.h>
#include <stdint.h>

#include "mxml.h"
#include <algorithm>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  mxmlLoadString(NULL, (const char *)Data, MXML_TEXT_CALLBACK);
  return 0;
}
```

こんな感じに書いてビルドした。

```sh
CC="clang -g -fsanitize=address,fuzzer"
make install
clang -g -fsanitize=address,fuzzer -I. fuzz.cc libmxml.a -o fuzz
 ./fuzz -dict=xml.dict -jobs=8 -workers=8  -detect_leaks=0 corpus
```

クラッシュしなかった。

### awk
いわずとしれたawkを選んだ。
awkはパーサではないが、パーサのようなものなので行けるだろうと思った。

と、書いて思い出したがこれはAFL++でやっていた。

```sh
afl-fuzz -i input -o output -M master ./a.out -f @@ input/NOTES
afl-fuzz -i input -o output -S slave1 ./a.out -f @@ input/NOTES
afl-fuzz -i input -o output -S slave2 ./a.out -f @@ input/NOTES
afl-fuzz -i input -o output -S slave3 ./a.out -f @@ input/NOTES
afl-fuzz -i input -o output -S slave4 ./a.out -f @@ input/NOTES
afl-fuzz -i input -o output -S slave5 ./a.out -f @@ input/NOTES
afl-fuzz -i input -o output -S slave6 ./a.out -f @@ input/NOTES
afl-fuzz -i input -o output -S slave7 ./a.out -f @@ input/NOTES
afl-fuzz -i input -o output -S slave8 ./a.out -f @@ input/NOTES
```
こんな感じにやっていた。
クラッシュはしたけど配布されているビルドではクラッシュしなかった。

## まとめ
LibFuzzer使いやすい。
それはそれとしてクラッシュ見つけるの大変である。
ファジングのターゲットを選ぶコツ知っている方がいれば教えてください。
