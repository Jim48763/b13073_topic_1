rule aefdafebccccccfeebaabda_exe {
strings:
        $s1 = "RkSwgkNb7p7E7qNONeN"
        $s2 = "$this.GridSize"
        $s3 = "STAThreadAttribute"
        $s4 = "ProductName"
        $s5 = "_CorExeMain"
        $s6 = "ComputeHash"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "IFormatProvider"
        $s10 = "set_MinimizeBox"
        $s11 = "customCultureName"
        $s12 = "SecondsRemaining"
        $s13 = "numberGroupSeparator"
        $s14 = "Synchronized"
        $s15 = "cmbEventType"
        $s16 = "UTF8Encoding"
        $s17 = "set_TabIndex"
        $s18 = "IAsyncResult"
        $s19 = "set_ShowIcon"
        $s20 = "dateTimeInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 617KB and
    4 of them
}
    
