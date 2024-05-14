rule cdbbbbecbddcfedfdeccbacdfa_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "GetConsoleOutputCP"
        $s3 = "LoadStringW"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "GetCurrentDirectoryW"
        $s10 = "            <requestedExecutionLevel"
        $s11 = "        <requestedPrivileges>"
        $s12 = "Microsoft Corporation"
        $s13 = "GetLocalTime"
        $s14 = "UpdateWindow"
        $s15 = "'5BNTWXUNA2!"
        $s16 = "</trustInfo>"
        $s17 = "GetWindowRect"
        $s18 = "    </security>"
        $s19 = "RegOpenKeyExW"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 375KB and
    4 of them
}
    
