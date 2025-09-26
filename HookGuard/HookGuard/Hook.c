#include "Global.h"

ZWCONTINUE g_ZwContinue = NULL;
RTLDISPATCHEXCEPTION g_RtlDispatchException = NULL;

LONG64 g_TotalCalls = 0;
LONG64 g_TotalResolved = 0;

DECLSPEC_NOINLINE VOID HookHandlePrivilegedInstruction(PEXCEPTION_RECORD exceptionRecord, PCONTEXT context)
{
    if (exceptionRecord->ExceptionCode != STATUS_PRIVILEGED_INSTRUCTION)
    {
        return;
    }

    if (*(PWORD)context->Rip != 0x220F)
    {
        return;
    }

    BYTE operand = *(PBYTE)(context->Rip + 2);
    operand &= 7;

    const UINT64* registers = &context->Rax;
    const UINT64 invalidCr3 = registers[operand];

    CR3 cr3;
    cr3.AsUInt = invalidCr3;
    cr3.Reserved3 = 0x0;
    cr3.AddressOfPageDirectory = GuardCrypt(cr3.AddressOfPageDirectory);

    InterlockedIncrement64(&g_TotalResolved);
    __writecr3(cr3.AsUInt);

    context->Rip += 3;

    g_ZwContinue(context, FALSE);
}

DECLSPEC_NOINLINE VOID HookFindRecord(VOID)
{
    CONTEXT current;
    RtlCaptureContext(&current);

    UNWIND_HISTORY_TABLE historyTable = { 0 };

    PCONTEXT frames = (PCONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT) * 10, 'dGkH');
    if (!frames)
    {
        return;
    }

    for (ULONG frame = 0; frame < 10; frame++)
    {
        ULONG64 imageBase;
        const PRUNTIME_FUNCTION runtimeFunction = RtlLookupFunctionEntry(current.Rip, &imageBase, &historyTable);
        if (!runtimeFunction)
        {
            break;
        }

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
        {
            break;
        }

        frames[frame] = current;

        if (!(current.Rip >= g_KdTrap && current.Rip < g_KdTrap + 0x50))
        {
            continue;
        }

        const ULONG64 originalIrql = *(ULONG64*)(frames[2].Rsp + sizeof(ULONG64) * 1);

        _enable();
        __writecr8(originalIrql);

        const PEXCEPTION_RECORD exceptionRecord = *(PEXCEPTION_RECORD*)current.Rsp;
        const PCONTEXT exceptionContext = *(PCONTEXT*)(current.Rsp + sizeof(ULONG64) * 10);

        if (exceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION)
        {
            HookHandlePrivilegedInstruction(exceptionRecord, exceptionContext);
        }

        g_RtlDispatchException(exceptionRecord, exceptionContext);
        break;
    }

    ExFreePool(frames);
}

DECLSPEC_NOINLINE ULONG64 HookEntry(ULONG64 arg1, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4)
{
    InterlockedIncrement64(&g_TotalCalls);
    HookFindRecord();
    return ((ULONG64(*)(ULONG64, ULONG64, ULONG64, ULONG64))(g_OriginalHandler))(arg1, arg2, arg3, arg4);
}
