#include "Global.h"

int main()
{
    printf("Downloading and parsing symbols...\n");
    Symbols::Pdb pdb("C:\\Windows\\System32\\ntoskrnl.exe");
    if (!pdb.Init())
    {
        printf("Failed to download and parse symbols!\n");
        return 1;
    }

    OFFSET_INFO offsetInfo;
    offsetInfo.KdpDebugRoutineSelect = pdb.GetRva("KdpDebugRoutineSelect");
    offsetInfo.HalpPerformanceCounter = pdb.GetRva("HalpPerformanceCounter");
    offsetInfo.HalpStallCounter = pdb.GetRva("HalpStallCounter");
    offsetInfo.HalpAlwaysOnCounter = pdb.GetRva("HalpAlwaysOnCounter");
    offsetInfo.KdTrap = pdb.GetRva("KdTrap");
    offsetInfo.KdpPrintString = pdb.GetRva("KdpPrintString");
    offsetInfo.KdDebuggerLock = pdb.GetRva("KdDebuggerLock");
    offsetInfo.NtGlobalFlag = pdb.GetRva("NtGlobalFlag");
    offsetInfo.ZwContinue = pdb.GetRva("ZwContinue");
    offsetInfo.RtlDispatchException = pdb.GetRva("RtlDispatchException");
    offsetInfo.PoAllProcIntrDisabled = pdb.GetRva("PoAllProcIntrDisabled");
    offsetInfo.KdIgnoreUmExceptions = pdb.GetRva("KdIgnoreUmExceptions");

    printf(" - NtGlobalFlag:             0x%p\n", reinterpret_cast<PVOID>(offsetInfo.NtGlobalFlag));
    printf(" - HalpPerformanceCounter:   0x%p\n", reinterpret_cast<PVOID>(offsetInfo.HalpPerformanceCounter));
    printf(" - HalpStallCounter:         0x%p\n", reinterpret_cast<PVOID>(offsetInfo.HalpStallCounter));
    printf(" - HalpAlwaysOnCounter:      0x%p\n", reinterpret_cast<PVOID>(offsetInfo.HalpAlwaysOnCounter));
    printf(" - KdTrap:                   0x%p\n", reinterpret_cast<PVOID>(offsetInfo.KdTrap));
    printf(" - KdpPrintString:           0x%p\n", reinterpret_cast<PVOID>(offsetInfo.KdpPrintString));
    printf(" - KdDebuggerLock:           0x%p\n", reinterpret_cast<PVOID>(offsetInfo.KdDebuggerLock));
    printf(" - KdpDebugRoutineSelect:    0x%p\n", reinterpret_cast<PVOID>(offsetInfo.KdpDebugRoutineSelect));
    printf(" - ZwContinue:               0x%p\n", reinterpret_cast<PVOID>(offsetInfo.ZwContinue));
    printf(" - RtlDispatchException:     0x%p\n", reinterpret_cast<PVOID>(offsetInfo.RtlDispatchException));
    printf(" - PoAllProcIntrDisabled:    0x%p\n", reinterpret_cast<PVOID>(offsetInfo.PoAllProcIntrDisabled));
    printf(" - KdIgnoreUmExceptions:     0x%p\n", reinterpret_cast<PVOID>(offsetInfo.KdIgnoreUmExceptions));

    printf("Press enter to continue...\n");
    std::string dummy;
    std::getline(std::cin, dummy);

    printf("Opening driver handle...\n");
    const HANDLE driver = CreateFileW(L"\\\\.\\HookGuard", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (!driver || driver == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open handle: %lu\n", GetLastError());
        return 1;
    }

    printf(" - Handle:                   0x%p\n", driver);

    printf("Setting offsets...\n");
    bool status = DeviceIoControl(driver, IOCTL_SET_OFFSETS, &offsetInfo, sizeof(offsetInfo), nullptr, 0, nullptr, nullptr);
    if (!status)
    {
        printf("Failed to set offsets: %lu\n", GetLastError());
        return 1;
    }

    printf("Registering process...\n");
    status = DeviceIoControl(driver, IOCTL_REGISTER_PROCESS, nullptr, 0, nullptr, 0, nullptr, nullptr);
    if (!status)
    {
        printf("Failed to register process: %lu\n", GetLastError());
        return 1;
    }

    while (true)
    {
        LOG_INFO info;
        status = DeviceIoControl(driver, IOCTL_LOG_INFO, nullptr, 0, &info, sizeof(info), nullptr, nullptr);
        if (!status)
        {
            printf("Failed to get log info: %lu\n", GetLastError());
            return 1;
        }

        printf("\r - Total: %llu, Resolved: %llu   ", info.TotalCalls, info.TotalResolved);

        Sleep(1000);
    }
}