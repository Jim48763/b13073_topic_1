rule caacdeccbcdadfcfaabecdd_exe {
strings:
        $s1 = "FlagsAttribute"
        $s2 = "RuntimeHelpers"
        $s3 = "GetProcessesByName"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "System.Data.SQLite"
        $s7 = "MB:n/-,#854"
        $s8 = "ComputeHash"
        $s9 = "op_Equality"
        $s10 = " AY08v6j&-!"
        $s11 = "VarFileInfo"
        $s12 = "w2\"WrbQ'&~"
        $s13 = "ProductName"
        $s14 = "_CorExeMain"
        $s15 = "FileDescription"
        $s16 = "FlushFinalBlock"
        $s17 = "a__5kklQqmjkui`"
        $s18 = "ResolveEventArgs"
        $s19 = "AEaewfqBB5dfk0fqqEd"
        $s20 = "dfY6Y6ao6nsMosvUoy"
condition:
    uint16(0) == 0x5a4d and filesize < 1244KB and
    4 of them
}
    
