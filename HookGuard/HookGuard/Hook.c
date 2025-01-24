#include "Global.h"

ZWCONTINUE g_ZwContinue = NULL;
RTLDISPATCHEXCEPTION g_RtlDispatchException = NULL;

LONG64 g_TotalCalls = 0;
LONG64 g_TotalResolved = 0;

DECLSPEC_NOINLINE VOID HookBreakpoint(VOID)
{
    *(UINT32*)(g_KernelBase + g_Offsets.KdDebuggerLock) = 0x0;
    *(UINT32*)(g_KernelBase + g_Offsets.NtGlobalFlag) = 0x0;
    __debugbreak();
}

VOID HookHandlePrivilegedInstruction(PEXCEPTION_RECORD exceptionRecord, PCONTEXT context)
{
    if (exceptionRecord->ExceptionCode != STATUS_PRIVILEGED_INSTRUCTION)
        return;

    // mov cr3, xxx
    if (*(PWORD)context->Rip != 0x220F)
        return;

    BYTE operand = *(PBYTE)(context->Rip + 2);
    operand &= 7;

    const UINT64* registers = &context->Rax;
    const UINT64 invalidCr3 = registers[operand];

    CR3 cr3;
    cr3.AsUInt = invalidCr3;
    cr3.Reserved3 = 0x0;
    cr3.AddressOfPageDirectory = GuardCrypt(cr3.AddressOfPageDirectory);

    KdpPrint("Fixing CR3 from 0x%p to 0x%p\n", invalidCr3, cr3.AsUInt);
    InterlockedIncrement64(&g_TotalResolved);
    __writecr3(cr3.AsUInt);

    context->Rip += 3;

    g_ZwContinue(context, FALSE);

    HookBreakpoint();
}

DECLSPEC_NOINLINE VOID HookFindRecord(VOID)
{
    CONTEXT current;
    RtlCaptureContext(&current);

    CONTEXT frames[10] = { 0 };
    for (ULONG frame = 0; frame < 10; frame++)
    {
        ULONG64 imageBase;
        const PRUNTIME_FUNCTION runtimeFunction = RtlLookupFunctionEntry(current.Rip, &imageBase, NULL);
        if (!runtimeFunction)
            break;

        PVOID handlerData;
        ULONG64 establisherFrame;
        KNONVOLATILE_CONTEXT_POINTERS nvContext = { 0 };
        RtlVirtualUnwind(
            UNW_FLAG_NHANDLER,
            imageBase,
            current.Rip,
            runtimeFunction,
            &current,
            &handlerData,
            &establisherFrame,
            &nvContext);

        if (!current.Rip)
            break;

        frames[frame] = current;

        if (!(current.Rip >= g_KdTrap && current.Rip < g_KdTrap + 0x50))
            continue;

        /*
         * 0: HookGuard!HookEntry+0x2d
         * 1: nt!KeStallExecutionProcessor+0x9b
         * 2: nt!KeFreezeExecution+0x110
         * 3: nt!KdEnterDebugger+0x6d
         * 4: nt!KdpReport+0x74
         * 5: nt!KdpTrap+0x160
         * 6: nt!KdTrap+0x2d
         */
        const ULONG64 originalIrql = *(ULONG64*)(frames[2].Rsp + sizeof(ULONG64) * 1);

        _enable();
        __writecr8(originalIrql);

        const PEXCEPTION_RECORD exceptionRecord = *(PEXCEPTION_RECORD*)current.Rsp;
        const PCONTEXT exceptionContext = *(PCONTEXT*)(current.Rsp + sizeof(ULONG64) * 10);

        KdpPrint("Handling exception with code 0x%p, flags 0x%lx, RIP 0x%p, IRQL %lu\n", exceptionRecord->ExceptionCode, exceptionRecord->ExceptionFlags, exceptionContext->Rip, originalIrql);

        if (exceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION)
            HookHandlePrivilegedInstruction(exceptionRecord, exceptionContext);

        if (exceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
            HookBreakpoint();

        g_RtlDispatchException(exceptionRecord, exceptionContext);
        break;
    }
}

DECLSPEC_NOINLINE ULONG64 HookEntry(ULONG64 arg1, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4)
{
    InterlockedIncrement64(&g_TotalCalls);
    HookFindRecord();
    return ((ULONG64(*)(ULONG64, ULONG64, ULONG64, ULONG64))(g_OriginalHandler))(arg1, arg2, arg3, arg4);
}