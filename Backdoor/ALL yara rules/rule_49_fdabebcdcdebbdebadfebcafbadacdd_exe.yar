rule fdabebcdcdebbdebadfebcafbadacdd_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "RegSetValueExW"
        $s4 = "CMTSilent=1"
        $s5 = "LoadStringW"
        $s6 = "pT%v0b\"1WU"
        $s7 = "DeviceIoControl"
        $s8 = "ProgramFilesDir"
        $s9 = "DialogBoxParamW"
        $s10 = "IsWindowVisible"
        $s11 = "`local vftable'"
        $s12 = "WindowsCodecs.dll"
        $s13 = "ARarHtmlClassName"
        $s14 = "GetShortPathNameW"
        $s15 = "Not enough memory"
        $s16 = "SetThreadPriority"
        $s17 = "TerminateProcess"
        $s18 = "DispatchMessageW"
        $s19 = "SetFilePointerEx"
        $s20 = "RemoveDirectoryW"
condition:
    uint16(0) == 0x5a4d and filesize < 462KB and
    4 of them
}
    
