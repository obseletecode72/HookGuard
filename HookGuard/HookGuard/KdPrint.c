#include "Global.h"

BOOLEAN g_EnableLogging = TRUE;
KDP_PRINT_STRING g_KdpPrintString = NULL;

void KdpPrint(PCSTR format, ...)
{
    if (!g_EnableLogging)
        return;

    va_list args;
    va_start(args, format);

    char buffer[256];
    vsprintf(buffer, format, args);

    STRING string;
    RtlInitString(&string, buffer);

    g_KdpPrintString(&string);

    va_end(args);
}