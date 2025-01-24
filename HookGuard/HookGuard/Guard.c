#include "Global.h"

ULONG64 g_KernelBase = 0;
ULONG64 g_OriginalHandler = 0;
ULONG64 g_KdTrap = 0;
OFFSET_INFO g_Offsets;
HANDLE g_TargetProcessId = 0;
ULONG64 g_Seed = 0;

VOID GuardProcessNotifyRoutine(HANDLE parentId, HANDLE processId, BOOLEAN create)
{
    UNREFERENCED_PARAMETER(parentId);

    if (create)
        return;

    if (processId != g_TargetProcessId)
        return;

    KdpPrint("Process %d is exiting, restoring...\n", processId);

    PCKPROCESS currentProcess = (PCKPROCESS)PsGetCurrentProcess();

    CR3 cr3;
    cr3.AsUInt = currentProcess->DirectoryTableBase;
    cr3.Reserved3 = 0x0;
    cr3.AddressOfPageDirectory = GuardCrypt(cr3.AddressOfPageDirectory);

    InterlockedExchangePointer((volatile PVOID*)&currentProcess->DirectoryTableBase, (PVOID)cr3.AsUInt);

    g_TargetProcessId = 0;
}

NTSTATUS GuardInitialize(VOID)
{
    static BOOLEAN initialized = FALSE;
    if (initialized)
        return STATUS_SUCCESS;

    g_Seed = __rdtsc();

    g_KernelBase = GetModuleBase("ntoskrnl.exe");
    if (!g_KernelBase)
        return STATUS_NOT_FOUND;

    g_KdTrap = g_KernelBase + g_Offsets.KdTrap;
    g_KdpPrintString = (KDP_PRINT_STRING)(g_KernelBase + g_Offsets.KdpPrintString);
    g_ZwContinue = (ZWCONTINUE)(g_KernelBase + g_Offsets.ZwContinue);
    g_RtlDispatchException = (RTLDISPATCHEXCEPTION)(g_KernelBase + g_Offsets.RtlDispatchException);

    *(UINT32*)(g_KernelBase + g_Offsets.KdpDebugRoutineSelect) = 0x1;
    *(UINT32*)(g_KernelBase + g_Offsets.KdDebuggerLock) = 0x1;
    *(UINT32*)(g_KernelBase + g_Offsets.PoAllProcIntrDisabled) = 0x1;
    *(UINT32*)(g_KernelBase + g_Offsets.NtGlobalFlag) = 0x1; // FLG_STOP_ON_EXCEPTION
    *(UINT32*)(g_KernelBase + g_Offsets.KdIgnoreUmExceptions) = 0x1;

    const ULONG64 counter = *(ULONG64*)(g_KernelBase + g_Offsets.HalpStallCounter);
    g_OriginalHandler = (ULONG64)InterlockedExchangePointer((volatile PVOID*)(counter + 0x70), (PVOID)HookEntry);

    NTSTATUS status = PsSetCreateProcessNotifyRoutine(GuardProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status))
        return status;

    initialized = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS GuardCleanup(VOID)
{
    if (!g_OriginalHandler)
        return STATUS_SUCCESS;

    *(UINT32*)(g_KernelBase + g_Offsets.NtGlobalFlag) = 0x0;
    *(UINT32*)(g_KernelBase + g_Offsets.KdIgnoreUmExceptions) = 0x0;
    *(UINT32*)(g_KernelBase + g_Offsets.KdDebuggerLock) = 0x0;

    const ULONG64 counter = *(ULONG64*)(g_KernelBase + g_Offsets.HalpStallCounter);
    InterlockedExchangePointer((volatile PVOID*)(counter + 0x70), (PVOID)g_OriginalHandler);

    g_OriginalHandler = 0;
    g_TargetProcessId = 0;

    NTSTATUS status = PsSetCreateProcessNotifyRoutine(GuardProcessNotifyRoutine, TRUE);
    if (!NT_SUCCESS(status))
        return status;

    return STATUS_SUCCESS;
}

ULONG64 GuardCrypt(ULONG64 value)
{
    value ^= 0x6734DEFE75238;
    value ^= 0x836278DDDFFFF;
    value ^= 0x999FFF11AA333;
    value ^= g_Seed;
    return value;
}

NTSTATUS GuardRegisterCurrentProcess(VOID)
{
    NTSTATUS status = GuardInitialize();
    if (!NT_SUCCESS(status))
        return status;

    if (g_TargetProcessId)
        return STATUS_ALREADY_REGISTERED;

    g_TargetProcessId = PsGetCurrentProcessId();

    PCKPROCESS currentProcess = (PCKPROCESS)PsGetCurrentProcess();

    CR3 cr3;
    cr3.AsUInt = currentProcess->DirectoryTableBase;
    cr3.Reserved3 = 0xFFFF;
    cr3.AddressOfPageDirectory = GuardCrypt(cr3.AddressOfPageDirectory);

    InterlockedExchangePointer((volatile PVOID*)&currentProcess->DirectoryTableBase, (PVOID)cr3.AsUInt);

    return STATUS_SUCCESS;
}