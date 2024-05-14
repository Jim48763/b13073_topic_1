rule aacbecfacefdffdfadafcacb_exe {
strings:
        $s1 = "RtlFreeAnsiString"
        $s2 = "[!!] Crash at addr 0x"
        $s3 = "_get_initial_narrow_environment"
        $s4 = "[-] Failed to load ntdll.dll"
        $s5 = "ExReleaseResourceLite"
        $s6 = "Intel Corporation "
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleA"
        $s13 = "__std_exception_copy"
        $s14 = "GetCurrentThreadId"
        $s15 = "NtLoadDriver"
        $s16 = "MSVCP140.dll"
        $s17 = "Durbanville1"
        $s18 = "KeBugCheckEx"
        $s19 = "FindFirstFileExW"
        $s20 = " wasn't found"
condition:
    uint16(0) == 0x5a4d and filesize < 127KB and
    4 of them
}
    
