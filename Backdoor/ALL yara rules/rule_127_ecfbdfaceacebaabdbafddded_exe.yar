rule ecfbdfaceacebaabdbafddded_exe {
strings:
        $s1 = "     name=\"wextract\""
        $s2 = "Sh%M}*e(`O>"
        $s3 = "j/z`i,2oN0b"
        $s4 = "(^&HyL9f~B`"
        $s5 = "ProductName"
        $s6 = "LoadStringA"
        $s7 = "2mkV4B&[+Pd"
        $s8 = "VarFileInfo"
        $s9 = "^h]g-XnF\"R"
        $s10 = "FileDescription"
        $s11 = "Command.com /c %s"
        $s12 = "GetShortPathNameA"
        $s13 = "GetModuleHandleW"
        $s14 = "RemoveDirectoryA"
        $s15 = "TerminateProcess"
        $s16 = "DispatchMessageA"
        $s17 = "SetCurrentDirectoryA"
        $s18 = "Microsoft Corporation"
        $s19 = "GetCurrentThreadId"
        $s20 = "EnableWindow"
condition:
    uint16(0) == 0x5a4d and filesize < 1179KB and
    4 of them
}
    
