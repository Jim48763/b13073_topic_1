rule cfbdfbcbeeaeceaeaaaaedccdddaf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "m_RangeDecoder"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "m_OutWindow"
        $s6 = "ProductName"
        $s7 = "_CorExeMain"
        $s8 = "@tLu2+? {6Y"
        $s9 = "VarFileInfo"
        $s10 = "%|nb_R#d=U'"
        $s11 = "RDfG5=1UXdg"
        $s12 = "FileDescription"
        $s13 = "SetDictionarySize"
        $s14 = "ResolveEventArgs"
        $s15 = "NumBitLevels"
        $s16 = "GCHandleType"
        $s17 = "C3:yBF$TCQH-"
        $s18 = "m_PosStateMask"
        $s19 = "UpdateShortRep"
        $s20 = "m_NumPosStates"
condition:
    uint16(0) == 0x5a4d and filesize < 678KB and
    4 of them
}
    
