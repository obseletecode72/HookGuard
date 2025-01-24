#pragma once

typedef PVOID(*KDP_PRINT_STRING)(PSTRING string);
extern KDP_PRINT_STRING g_KdpPrintString;

extern BOOLEAN g_EnableLogging;

VOID KdpPrint(PCSTR format, ...);