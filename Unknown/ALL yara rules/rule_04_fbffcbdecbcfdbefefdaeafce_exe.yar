rule fbffcbdecbcfdbefefdaeafce_exe {
strings:
        $s1 = "DetachFromProcess"
        $s2 = "set_bossesKilledValueLabel"
        $s3 = "GetPlayerCharacterType"
        $s4 = "updateDefeatedBossesCount"
        $s5 = "get_ButtonDraw"
        $s6 = "RuntimeHelpers"
        $s7 = " ~ 3.14159265358979323846"
        $s8 = "get_TransmitTimestamp"
        $s9 = "AuthenticationMode"
        $s10 = "get_RootDispersion"
        $s11 = "RuntimeFieldHandle"
        $s12 = "STAThreadAttribute"
        $s13 = "DesignerGeneratedAttribute"
        $s14 = "m_BugReport"
        $s15 = "TBFOVRADisp"
        $s16 = "MsgBoxStyle"
        $s17 = "get_TBFOVRA"
        $s18 = "ProductName"
        $s19 = "_CorExeMain"
        $s20 = "TBFOVHeight"
condition:
    uint16(0) == 0x5a4d and filesize < 845KB and
    4 of them
}
    