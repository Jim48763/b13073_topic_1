rule dacfeecdccfaecaffcefee_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "set_SizingGrip"
        $s3 = "\\dagger_cheap.png"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "InternalMemberValu"
        $s7 = "DesignerGeneratedAttribute"
        $s8 = "Angelic War"
        $s9 = "_CorExeMain"
        $s10 = "set_grpInfo"
        $s11 = "ProductName"
        $s12 = "VarFileInfo"
        $s13 = "System.Linq"
        $s14 = "ThreadStaticAttribute"
        $s15 = "KeyEventHandler"
        $s16 = "set_MinimizeBox"
        $s17 = "SafeLibraryHand"
        $s18 = "set_UseWaitCursor"
        $s19 = "get_pnlInventory"
        $s20 = "_testFillPlayerSheet"
condition:
    uint16(0) == 0x5a4d and filesize < 1236KB and
    4 of them
}
    
