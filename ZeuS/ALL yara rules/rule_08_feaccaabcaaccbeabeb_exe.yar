rule feaccaabcaaccbeabeb_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "<EX;:\"j3X}K}"
        $s4 = "GetSystemTimeAsFileTime"
        $s5 = "Y nBsHLKi|"
        $s6 = "mN <FuIOjP"
        $s7 = "Ynq>u/Ce*I"
        $s8 = "Dd}V\">Iu#"
        $s9 = "\" k3.#DB*"
        $s10 = "ExitProcess"
        $s11 = "Piriform Ltd"
        $s12 = "FindMediaType"
        $s13 = "GetProcAddress"
        $s14 = "OriginalFilename"
        $s15 = "VirtualAlloc"
        $s16 = "CreateProcessA"
        $s17 = "BP%L\\iD-c"
        $s18 = "qpGo\\&Kr|"
        $s19 = "Translation"
        $s20 = "LoadLibraryA"
condition:
    uint16(0) == 0x5a4d and filesize < 1002KB and
    4 of them
}
    
