rule aedcdfedfacacacdebdabfcbda_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "RegSetValueExA"
        $s4 = "ren Arbeitsordner an."
        $s5 = "c+x[<02E4mJ"
        $s6 = "YOlcA(jZgr@"
        $s7 = "ProductName"
        $s8 = "LoadStringA"
        $s9 = ".\"_}<'u{7X"
        $s10 = "1<j%H3()N=["
        $s11 = "VarFileInfo"
        $s12 = "Q}t=]biDKO|"
        $s13 = "FileDescription"
        $s14 = "Command.com /c %s"
        $s15 = "GetShortPathNameA"
        $s16 = "TerminateProcess"
        $s17 = "Befehlsoptionen:"
        $s18 = "RemoveDirectoryA"
        $s19 = "Temporary folder"
        $s20 = "DispatchMessageA"
condition:
    uint16(0) == 0x5a4d and filesize < 832KB and
    4 of them
}
    
