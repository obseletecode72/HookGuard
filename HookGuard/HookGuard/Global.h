#pragma once

#include <ntifs.h>
#include <minwindef.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>

#include "Defines.h"
#include "Utilities.h"
#include "Device.h"
#include "Shared.h"
#include "Guard.h"
#include "Hook.h"
#include "KdPrint.h"
#include "IA32.h"

#define Log(x, ...) DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[HookGuard] " x "\n", __VA_ARGS__)