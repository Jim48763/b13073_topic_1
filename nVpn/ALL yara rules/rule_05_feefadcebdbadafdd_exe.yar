rule feefadcebdbadafdd_exe {
strings:
        $s1 = "B~BkM+E?rJP+EIsJP"
        $s2 = "Mt.Eu&Xv.Xw6Xx>Xy"
        $s3 = "aBBLjbBBLDYjcBBLDXjdBBLlBUrEBLCBBCBBSbSJBBOTEjfBBLLb"
        $s4 = "D_KGBCZQCJBFC_GJZJGbDC^JFBCJPGbDJJJGbBT"
        $s5 = "@CX@CUMSMnFSIUJBKSI"
        $s6 = "BBLSI@CUPSPnIBSOUImPSNY"
        $s7 = "BBLj0CBHMInDme"
        $s8 = "p-jnBBHEXjyBBHlBBBUrFBaBBBGBBSYLD"
        $s9 = "EBB]lhDEFj}BBHldDEj{BBLldDEj|BBLl`Dj}BBLl"
        $s10 = "BBHEFGPFjxDBHLmSDj"
        $s11 = "STAThreadAttribute"
        $s12 = "ProductName"
        $s13 = "FBCM[LIHD^S"
        $s14 = "_CorExeMain"
        $s15 = "VarFileInfo"
        $s16 = "X@ENJn\\TCcBBBBAAAATCj"
        $s17 = "Version 0.3.1.0"
        $s18 = "CBHV@CmCXNJn\\D"
        $s19 = "comboBoxAddingF"
        $s20 = "set_MinimizeBox"
condition:
    uint16(0) == 0x5a4d and filesize < 296KB and
    4 of them
}
    
