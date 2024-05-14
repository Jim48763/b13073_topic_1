rule fabfdecdfcbcacecaacdcb_exe {
strings:
        $s1 = "_CorExeMain"
        $s2 = "GetResponseStream"
        $s3 = "get_StartInfo"
        $s4 = "get_EntryPoint"
        $s5 = "set_UseShellExecute"
        $s6 = "StringSplitOptions"
        $s7 = "211204093423Z0w1\"0 "
        $s8 = "set_Arguments"
        $s9 = "set_FileName"
        $s10 = "HttpWebRequest"
        $s11 = "MethodInfo"
        $s12 = "MethodBase"
        $s13 = "mscoree.dll"
        $s14 = "Application"
        $s15 = "WaitForExit"
        $s16 = "MemoryStream"
        $s17 = "CookieContainer"
        $s18 = "Babdacffdcfcabbbeedbcabac.exe"
        $s19 = "Conversions"
        $s20 = "6.627.790.432"
condition:
    uint16(0) == 0x5a4d and filesize < 31KB and
    4 of them
}
    
