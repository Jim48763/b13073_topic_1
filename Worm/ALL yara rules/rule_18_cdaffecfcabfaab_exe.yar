rule cdaffecfcabfaab_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "Uninitialized row"
        $s3 = "gamma table being rebuilt"
        $s4 = "CreateIoCompletionPort"
        $s5 = "invalid with alpha channel"
        $s6 = "non-positive height"
        $s7 = "Directory not empty"
        $s8 = "RegSetValueExA"
        $s9 = "Runtime Error!"
        $s10 = "A512548E76954B6E92C21055517615B0"
        $s11 = "invalid distance code"
        $s12 = "No child processes"
        $s13 = "Default IME"
        $s14 = "ProductName"
        $s15 = "Ctrl+PageUp"
        $s16 = "LocalSystem"
        $s17 = "FD@ul9L$(}f"
        $s18 = "4i5U6B738%9"
        $s19 = "FileDescription"
        $s20 = "Invalid IHDR data"
condition:
    uint16(0) == 0x5a4d and filesize < 985KB and
    4 of them
}
    
