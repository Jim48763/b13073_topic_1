rule afcacbfeeccdbcdaabcadfd_exe {
strings:
        $s1 = "TooManyAlternates"
        $s2 = "_ENABLE_PROFILING"
        $s3 = "Get_StringDecrypter"
        $s4 = "ManagementBaseObject"
        $s5 = "Get_IsRemoveOn"
        $s6 = "CerArrayList`1"
        $s7 = "RuntimeFieldHandle"
        $s8 = "PrePrepareMethodAttribute"
        $s9 = "ProductName"
        $s10 = "_CorExeMain"
        $s11 = "Get_SPARENT"
        $s12 = "ComputeHash"
        $s13 = "op_Equality"
        $s14 = "VarFileInfo"
        $s15 = "oeajmIknghi"
        $s16 = "Get_PreserveEventRids"
        $s17 = "FileDescription"
        $s18 = "FlushFinalBlock"
        $s19 = "lpApplicationName"
        $s20 = "get_IsConstructor"
condition:
    uint16(0) == 0x5a4d and filesize < 417KB and
    4 of them
}
    
