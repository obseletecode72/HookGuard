#pragma once

typedef PVOID(*ZWCONTINUE)(PCONTEXT context, BOOLEAN removeAlert);
extern ZWCONTINUE g_ZwContinue;

typedef BOOLEAN(*RTLDISPATCHEXCEPTION)(PEXCEPTION_RECORD exceptionRecord, PCONTEXT context);
extern RTLDISPATCHEXCEPTION g_RtlDispatchException;

extern LONG64 g_TotalCalls;
extern LONG64 g_TotalResolved;

ULONG64 HookEntry(ULONG64 arg1, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);