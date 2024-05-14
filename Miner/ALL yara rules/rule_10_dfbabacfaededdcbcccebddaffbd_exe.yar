rule dfbabacfaededdcbcccebddaffbd_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "_CorExeMain"
        $s4 = "FileDescription"
        $s5 = "--load-extension="
        $s6 = "get_CurrentDirectory"
        $s7 = "    </security>"
        $s8 = "DebuggingModes"
        $s9 = "o=M>_}Vgwvfvvw"
        $s10 = "\\launcher.exe"
        $s11 = "LegalTrademarks"
        $s12 = "Copyright "
        $s13 = "$`>\"*nzAR"
        $s14 = "DebuggableAttribute"
        $s15 = "</assembly>"
        $s16 = "\\config.txt"
        $s17 = "set_Arguments"
        $s18 = "OriginalFilename"
        $s19 = "set_FileName"
        $s20 = "ConsoleKeyInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 199KB and
    4 of them
}
    
