#pragma once

NTSTATUS DeviceCreateClose(PDEVICE_OBJECT deviceObject, PIRP irp);
NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp);