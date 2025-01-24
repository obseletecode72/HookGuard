#include "Global.h"

char* CompareIgnoreCase(PCSTR haystack, const PCSTR needle)
{
    do
    {
        PCSTR h = haystack;
        PCSTR n = needle;
        while (tolower((unsigned char)(*h)) == tolower((unsigned char)(*n)) && *n)
        {
            h++;
            n++;
        }
        if (*n == 0)
            return (char*)haystack;
    } while (*haystack++);
    return NULL;
}

ULONG64 GetModuleBase(const PCSTR moduleName)
{
    PVOID address = NULL;
    ULONG size = 0;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return 0;

    const PSYSTEM_MODULE_INFORMATION moduleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
    if (!moduleList)
        return 0;

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, NULL);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(moduleList);
        return 0;
    }

    for (ULONG_PTR i = 0; i < moduleList->ulModuleCount; i++)
    {
        ULONG64 pointer = (ULONG64)&moduleList->Modules[i];
        pointer += sizeof(SYSTEM_MODULE);
        if (pointer > ((ULONG64)moduleList + size))
            break;

        SYSTEM_MODULE module = moduleList->Modules[i];
        module.ImageName[255] = '\0';
        if (CompareIgnoreCase(module.ImageName, moduleName))
        {
            address = module.Base;
            break;
        }
    }

    ExFreePool(moduleList);
    return (ULONG64)address;
}

#define IN_RANGE(x, a, b) ((x) >= (a) && (x) <= (b))
#define GET_BITS(x) (IN_RANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xA) : (IN_RANGE(x, '0', '9') ? (x - '0') : 0))
#define GET_BYTE(a, b) ((GET_BITS(a) << 4) | GET_BITS(b))

ULONG64 FindPattern(const PVOID baseAddress, const ULONG64 size, const PCSTR pattern)
{
    BYTE* firstMatch = NULL;
    PCSTR currentPattern = pattern;

    BYTE* start = (BYTE*)baseAddress;
    const BYTE* end = start + size;

    for (BYTE* current = start; current < end; current++)
    {
        const BYTE byte = currentPattern[0];
        if (!byte)
            return (ULONG64)firstMatch;

        if (byte == '?' || *current == GET_BYTE(byte, currentPattern[1]))
        {
            if (!firstMatch)
                firstMatch = current;
            if (!currentPattern[2])
                return (ULONG64)firstMatch;
            currentPattern += (byte == '?') ? 2 : 3;
        }
        else
        {
            currentPattern = pattern;
            firstMatch = NULL;
        }
    }

    return 0;
}

ULONG64 FindPatternImage(const PVOID base, const PCSTR pattern)
{
    ULONG64 match = 0;

    const PIMAGE_NT_HEADERS64 headers = (PIMAGE_NT_HEADERS64)((ULONG64)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
    for (USHORT i = 0; i < headers->FileHeader.NumberOfSections; ++i)
    {
        const PIMAGE_SECTION_HEADER section = &sections[i];
        if (!memcmp(section->Name, ".text", 5) || *(ULONG32*)section->Name == 'EGAP')
        {
            match = FindPattern((PVOID)((ULONG64)base + section->VirtualAddress), section->Misc.VirtualSize, pattern);
            if (match)
                break;
        }
    }

    return match;
}