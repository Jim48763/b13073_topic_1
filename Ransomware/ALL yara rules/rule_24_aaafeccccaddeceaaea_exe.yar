rule aaafeccccaddeceaaea_exe {
strings:
        $s1 = "    </security>"
        $s2 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD"
        $s3 = "ExitProcess"
        $s4 = "KERNEL32.dll"
        $s5 = "CoUninitialize"
        $s6 = "VSSAPI.DLL"
        $s7 = "ole32.dll"
        $s8 = "`.rdata"
        $s9 = "@.rsrc"
        $s10 = "RichU"
        $s11 = "RSDS\\"
        $s12 = ".text"
condition:
    uint16(0) == 0x5a4d and filesize < 9KB and
    4 of them
}
    
