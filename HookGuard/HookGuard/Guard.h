#pragma once

extern ULONG64 g_KernelBase;
extern ULONG64 g_OriginalHandler;
extern ULONG64 g_KdTrap;
extern OFFSET_INFO g_Offsets;
extern HANDLE g_TargetProcessId;
extern ULONG64 g_Seed;

NTSTATUS GuardInitialize(VOID);
NTSTATUS GuardCleanup(VOID);
ULONG64 GuardCrypt(ULONG64 value);
NTSTATUS GuardRegisterCurrentProcess(VOID);