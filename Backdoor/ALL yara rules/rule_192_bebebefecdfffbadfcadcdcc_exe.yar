rule bebebefecdfffbadfcadcdcc_exe {
strings:
        $s1 = "_CorExeMain"
        $s2 = "IFormatProvider"
        $s3 = "System.Resources"
        $s4 = "StringBuilder"
        $s5 = "GetResponseStream"
        $s6 = "NewLateBinding"
        $s7 = "set_AccessibleName"
        $s8 = "StringSplitOptions"
        $s9 = "Sxysxtem.Rexfxlxexcxtxixoxn.Axsxsxexmxblxxy"
        $s10 = "IDisposable"
        $s11 = "CultureInfo"
        $s12 = "timeout {0}"
        $s13 = "IEnumerable"
        $s14 = "AppWinStyle"
        $s15 = "RichTextBox"
        $s16 = "set_Capacity"
        $s17 = "GetEnumerator"
        $s18 = "HttpStatusCode"
        $s19 = "ClearProjectError"
        $s20 = "HttpWebRequest"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
