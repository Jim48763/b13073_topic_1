rule fccefadbbabbbbaafafdffcbaeaabdb_exe {
strings:
        $s1 = "IPInterfaceProperties"
        $s2 = "ManagementBaseObject"
        $s3 = "get_UnicastAddresses"
        $s4 = "DescriptionAttribute"
        $s5 = "RuntimeHelpers"
        $s6 = "StringComparer"
        $s7 = "GetSubKeyNames"
        $s8 = "CSharpCodeProvider"
        $s9 = "RuntimeFieldHandle"
        $s10 = "ConsoleApplication"
        $s11 = "get_ProcessorCount"
        $s12 = "STAThreadAttribute"
        $s13 = "IOException"
        $s14 = "Mix9IjP5AfN"
        $s15 = "PY:J-D[a5EU"
        $s16 = "_CorExeMain"
        $s17 = "SocketFlags"
        $s18 = "ComputeHash"
        $s19 = "get_Ordinal"
        $s20 = "PixelFormat"
condition:
    uint16(0) == 0x5a4d and filesize < 1411KB and
    4 of them
}
    
