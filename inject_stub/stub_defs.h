#pragma once

#include <Windows.h>

#pragma pack(push, 1)

typedef struct _TRAMPLONE32 {
	UCHAR opcode;
	DWORD addr;
} TRAMPLONE32, *PTRAMPLONE32;

typedef struct _TRAMPLONE64 {
	WORD opcode;
	ULONGLONG addr;
	WORD opcode2;
} TRAMPLONE64, *PTRAMPLONE64;

#pragma pack(pop)
