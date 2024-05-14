rule eeabacfabafccdfabbcffeeaecb_exe {
strings:
        $s1 = "System.Data.OleDb"
        $s2 = "AutoPropertyValue"
        $s3 = "kneqewZem-;B==eR:"
        $s4 = "get_lblEventDetails"
        $s5 = "set_BtnManageRaceResults"
        $s6 = "set_RaceTimeID"
        $s7 = "RuntimeHelpers"
        $s8 = "get_IsCanceled"
        $s9 = "Confirm Delete"
        $s10 = "GetRaceEventTitles"
        $s11 = "ResetControlValues"
        $s12 = "STAThreadAttribute"
        $s13 = "AuthenticationMode"
        $s14 = "DesignerGeneratedAttribute"
        $s15 = "^V<YTxZLv3a"
        $s16 = "My.Computer"
        $s17 = "m_FRMEvents"
        $s18 = "ay-`LEC^zH."
        $s19 = "_CorExeMain"
        $s20 = "$T04wUpdaS6"
condition:
    uint16(0) == 0x5a4d and filesize < 870KB and
    4 of them
}
    
