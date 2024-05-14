rule bbbeccfaedabdceaefeccbbdf_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "RegSetValueExA"
        $s4 = "LoadStringA"
        $s5 = "UDryIohQ\"2"
        $s6 = "M+Zu1!kIC\""
        $s7 = "&}DS,Tp_CnO"
        $s8 = "VarFileInfo"
        $s9 = "ProductName"
        $s10 = "FileDescription"
        $s11 = "GetShortPathNameA"
        $s12 = "Command.com /c %s"
        $s13 = "RemoveDirectoryA"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleA"
        $s16 = "Temporary folder"
        $s17 = "GetCurrentDirectoryA"
        $s18 = "Do you want to continue?"
        $s19 = "GetCurrentThreadId"
        $s20 = "DecryptFileA"
condition:
    uint16(0) == 0x5a4d and filesize < 996KB and
    4 of them
}
    