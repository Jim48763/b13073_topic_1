rule ccdedecebaafedcdeefeec_exe {
strings:
        $s1 = "EVariantBadIndexError"
        $s2 = "DuplicateDevicePath"
        $s3 = "gEfiPcAnsiGuid"
        $s4 = "RegSetValueExA"
        $s5 = "Warning Write Failure"
        $s6 = "PoolAllocationType"
        $s7 = "LibRuntimeDebugOut"
        $s8 = "Heap32First"
        $s9 = "LoadStringA"
        $s10 = "ir;y|H9m#fF"
        $s11 = "DeviceIoControl"
        $s12 = "GetKeyboardType"
        $s13 = "GetThreadLocale"
        $s14 = "TerminateProcess"
        $s15 = "Division by zero"
        $s16 = "GetModuleHandleA"
        $s17 = "SimplePointerProtocol"
        $s18 = "GetCurrentThreadId"
        $s19 = "ConOutDevice"
        $s20 = "DrvSupEfiVer"
condition:
    uint16(0) == 0x5a4d and filesize < 155KB and
    4 of them
}
    
