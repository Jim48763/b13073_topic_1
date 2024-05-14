rule ffadababccaeeeaeffdceabfe_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "m_RangeDecoder"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "m_OutWindow"
        $s6 = "m_HighCoder"
        $s7 = "_CorExeMain"
        $s8 = "VarFileInfo"
        $s9 = "ProductName"
        $s10 = "FileDescription"
        $s11 = "ResolveEventArgs"
        $s12 = "GCHandleType"
        $s13 = "NumBitLevels"
        $s14 = "UpdateShortRep"
        $s15 = "m_PosStateMask"
        $s16 = "m_NumPosStates"
        $s17 = "DebuggingModes"
        $s18 = "LegalTrademarks"
        $s19 = "InitializeArray"
        $s20 = "PN)ZgmR]o#"
condition:
    uint16(0) == 0x5a4d and filesize < 35KB and
    4 of them
}
    
