rule afcbefeeeafbecddfeedac_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "RegSetValueExA"
        $s4 = "Dm?FVL9]&KN"
        $s5 = "LVS86.{+ Og"
        $s6 = "{d,zOnTm&UI"
        $s7 = "VarFileInfo"
        $s8 = "a0U6# 4pl$2"
        $s9 = "ProductName"
        $s10 = "j(GEv9gHF$<"
        $s11 = "#+|X)./iyAR"
        $s12 = "LoadStringA"
        $s13 = "FileDescription"
        $s14 = "Command.com /c %s"
        $s15 = "GetShortPathNameA"
        $s16 = "GetModuleHandleA"
        $s17 = "RemoveDirectoryA"
        $s18 = "DispatchMessageA"
        $s19 = "TerminateProcess"
        $s20 = "Temporary folder"
condition:
    uint16(0) == 0x5a4d and filesize < 1360KB and
    4 of them
}
    
