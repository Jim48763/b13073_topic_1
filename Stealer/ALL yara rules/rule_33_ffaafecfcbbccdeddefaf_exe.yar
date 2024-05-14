rule ffaafecfcbbccdeddefaf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "$this.GridSize"
        $s3 = "FlagsAttribute"
        $s4 = "dnXsIuIl331X6v1LXn"
        $s5 = "JXjhUjjsxV3ZjSVVoN"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "ProductName"
        $s9 = "_CorExeMain"
        $s10 = "ComputeHash"
        $s11 = ";y3`s!{TV1b"
        $s12 = "]-;'N\"zW)M"
        $s13 = "|z:;$D8hnCk"
        $s14 = "op_Equality"
        $s15 = "VarFileInfo"
        $s16 = "FileDescription"
        $s17 = "FlushFinalBlock"
        $s18 = "customCultureName"
        $s19 = "get_ModuleHandle"
        $s20 = "numberGroupSeparator"
condition:
    uint16(0) == 0x5a4d and filesize < 2053KB and
    4 of them
}
    
