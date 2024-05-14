rule aefbdbbebdeccbdffeecae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "JAG~$2F&J*F4J F2J1D"
        $s4 = ")88Dod_(r8I[=j"
        $s5 = "F6<k? 18|4J"
        $s6 = "ProductName"
        $s7 = ">3R&ol+.-/!"
        $s8 = "B8v^3za}-SF"
        $s9 = "LoadStringA"
        $s10 = "VarFileInfo"
        $s11 = "9syoY3O%}@g"
        $s12 = "rbV%Xz_e#m!"
        $s13 = "FileDescription"
        $s14 = "exe\\wextract.dbg"
        $s15 = "Command.com /c %s"
        $s16 = "GetShortPathNameA"
        $s17 = "RemoveDirectoryA"
        $s18 = "Temporary folder"
        $s19 = "DispatchMessageA"
        $s20 = "GetModuleHandleA"
condition:
    uint16(0) == 0x5a4d and filesize < 1308KB and
    4 of them
}
    
