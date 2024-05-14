rule Ransomware_CryptoLocker_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetWindowTheme"
        $s3 = "CoInitializeEx"
        $s4 = "GdipGetImageHeight"
        $s5 = "IsWindowVisible"
        $s6 = "DialogBoxParamW"
        $s7 = "SetThreadPriority"
        $s8 = "PathAddBackslashW"
        $s9 = "UnregisterClassW"
        $s10 = "SetFilePointerEx"
        $s11 = "GetModuleHandleW"
        $s12 = "GetComputerNameW"
        $s13 = "DispatchMessageW"
        $s14 = "CreateCompatibleDC"
        $s15 = "GetCurrentThreadId"
        $s16 = "GetTickCount"
        $s17 = "+be IuwBRyR-"
        $s18 = "UpdateWindow"
        $s19 = "SysListView32"
        $s20 = "RegEnumKeyExW"
condition:
    uint16(0) == 0x5a4d and filesize < 343KB and
    4 of them
}
    
