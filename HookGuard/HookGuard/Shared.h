#pragma once

#define IOCTL_REGISTER_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_OFFSETS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LOG_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _OFFSET_INFO
{
    ULONG64 PoAllProcIntrDisabled;
    ULONG64 HalpPerformanceCounter;
    ULONG64 HalpStallCounter;
    ULONG64 HalpAlwaysOnCounter;
    ULONG64 KdpDebugRoutineSelect;
    ULONG64 KdDebuggerLock;
    ULONG64 KdTrap;
    ULONG64 KdpPrintString;
    ULONG64 NtGlobalFlag;
    ULONG64 ZwContinue;
    ULONG64 RtlDispatchException;
    ULONG64 KdIgnoreUmExceptions;
} OFFSET_INFO;

typedef struct _LOG_INFO
{
    ULONG64 TotalCalls;
    ULONG64 TotalResolved;
} LOG_INFO;