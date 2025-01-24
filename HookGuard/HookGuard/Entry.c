#include "Global.h"

#define NT_DEVICE_NAME      L"\\Device\\HookGuard"
#define DOS_DEVICE_NAME     L"\\DosDevices\\HookGuard"

VOID DriverUnload(PDRIVER_OBJECT driverObject)
{
    GuardCleanup();

    UNICODE_STRING dosDeviceName;
    RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);

    IoDeleteSymbolicLink(&dosDeviceName);

    if (driverObject->DeviceObject)
        IoDeleteDevice(driverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    UNICODE_STRING ntDeviceName;
    RtlInitUnicodeString(&ntDeviceName, NT_DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(driverObject, 0, &ntDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
        FALSE, &driverObject->DeviceObject);
    if (!NT_SUCCESS(status))
        return status;

    UNICODE_STRING dosDeviceName;
    RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);

    status = IoCreateSymbolicLink(&dosDeviceName, &ntDeviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(driverObject->DeviceObject);
        return status;
    }

    driverObject->DriverUnload = DriverUnload;
    driverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    driverObject->DeviceObject->Flags |= DO_DIRECT_IO;
    driverObject->DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}