rule baceaddfecbebaddbcdeccbff_exe {
strings:
        $s1 = "get_IgnoredProperties"
        $s2 = "IDifferenceFormatter"
        $s3 = "System.Linq"
        $s4 = "op_Equality"
        $s5 = "_CorExeMain"
        $s6 = "nzTkM-*Jg[K"
        $s7 = "IGrouping`2"
        $s8 = "VarFileInfo"
        $s9 = "SkipDefault"
        $s10 = "ReflectionCache"
        $s11 = "<.cctor>b__46_0"
        $s12 = "FileDescription"
        $s13 = "IsPropertyIgnored"
        $s14 = "VisitingProperty"
        $s15 = "DebuggerHiddenAttribute"
        $s16 = "IgnoreSourceProperty"
        $s17 = "._\\pW8o{yk0"
        $s18 = "AsEnumerable"
        $s19 = "Expression`1"
        $s20 = "AppendFormat"
condition:
    uint16(0) == 0x5a4d and filesize < 946KB and
    4 of them
}
    
