rule fcdedcdbfbdcecbdbbddbda_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "%UALKY3}O9C"
        $s6 = "DialogBoxParamA"
        $s7 = "GetKeyboardType"
        $s8 = "GetThreadLocale"
        $s9 = "GetShortPathNameA"
        $s10 = "DispatchMessageA"
        $s11 = "GetModuleHandleA"
        $s12 = "CreateCompatibleDC"
        $s13 = "GetCurrentThreadId"
        $s14 = "SHBrowseForFolderA"
        $s15 = "EnableWindow"
        $s16 = "GetLocalTime"
        $s17 = "FPUMaskValue"
        $s18 = "SetEndOfFile"
        $s19 = "GetTickCount"
        $s20 = "RegEnumValueA"
condition:
    uint16(0) == 0x5a4d and filesize < 280KB and
    4 of them
}
    
