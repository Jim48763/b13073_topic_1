rule acbadcaadbdcfeafbeadbbfdcaf_dll {
strings:
        $s1 = "cross device link"
        $s2 = "CreateThreadpoolTimer"
        $s3 = "<dev:version></dev:version>"
        $s4 = "executable format error"
        $s5 = "result out of range"
        $s6 = "directory not empty"
        $s7 = "invalid string position"
        $s8 = "operation canceled"
        $s9 = "LC_MONETARY"
        $s10 = "VarFileInfo"
        $s11 = "ProductName"
        $s12 = "tdognmp; -e"
        $s13 = "sie:>c7l1mp"
        $s14 = "ity</maml:name>"
        $s15 = "FileDescription"
        $s16 = "`local vftable'"
        $s17 = "spanish-venezuela"
        $s18 = "rray'.&quot;.   "
        $s19 = "GetModuleHandleA"
        $s20 = "SetFilePointerEx"
condition:
    uint16(0) == 0x5a4d and filesize < 853KB and
    4 of them
}
    
