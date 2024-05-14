rule adbebbaeacdfbdedfddbda_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "get_IsTerminating"
        $s3 = "nana.Form1.resources"
        $s4 = "Software\\Red Gate\\"
        $s5 = "RuntimeHelpers"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "WXDO[67,nzs"
        $s9 = "?tuws~SGKyC"
        $s10 = "ProductName"
        $s11 = "c`1bra7wR=S"
        $s12 = "WzbFn'B%C6w"
        $s13 = "C@dNSMgV>DR"
        $s14 = "-+31WX@G`U "
        $s15 = "{X+AS%:@b6&"
        $s16 = "_CorExeMain"
        $s17 = "LastIndexOf"
        $s18 = "WindowStyle"
        $s19 = "TUC;^YR!vw0"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 870KB and
    4 of them
}
    
