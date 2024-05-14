rule feabceebbafabdfcbfdfdffe_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "op_Equality"
        $s3 = "_CorExeMain"
        $s4 = "AddMessageFilter"
        $s5 = "Greater Manchester1"
        $s6 = "6b23cc3c-331b-438a-9ba7-9b3b273d3938"
        $s7 = "HttpClientHandler"
        $s8 = "ISerializableItem"
        $s9 = "GetObjectValue"
        $s10 = "get_EntryPoint"
        $s11 = "Jersey City1"
        $s12 = "get_HasValue"
        $s13 = "HttpWebRequest"
        $s14 = "MethodInfo"
        $s15 = "MethodBase"
        $s16 = "System.Net.Http"
        $s17 = "mscoree.dll"
        $s18 = "Application"
        $s19 = "ToByteArray"
        $s20 = "BitConverter"
condition:
    uint16(0) == 0x5a4d and filesize < 3898KB and
    4 of them
}
    
