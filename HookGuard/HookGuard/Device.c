#include "Global.h"

NTSTATUS DeviceCreateClose(PDEVICE_OBJECT deviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    const PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);
    switch (io->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SET_OFFSETS:
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(OFFSET_INFO))
        {
            irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            irp->IoStatus.Information = 0;
            break;
        }

        const OFFSET_INFO* offsets = (OFFSET_INFO*)irp->AssociatedIrp.SystemBuffer;
        if (!offsets)
        {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            break;
        }

        g_Offsets = *offsets;

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        break;
    case IOCTL_REGISTER_PROCESS:
        irp->IoStatus.Status = GuardRegisterCurrentProcess();
        irp->IoStatus.Information = 0;
        break;
    case IOCTL_LOG_INFO:
        if (io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(LOG_INFO))
        {
            irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            irp->IoStatus.Information = 0;
            break;
        }

        LOG_INFO* log = (LOG_INFO*)irp->AssociatedIrp.SystemBuffer;
        if (!log)
        {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            break;
        }

        log->TotalCalls = g_TotalCalls;
        log->TotalResolved = g_TotalResolved;

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(LOG_INFO);
        break;
    default:
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        irp->IoStatus.Information = 0;
        break;
    }

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}