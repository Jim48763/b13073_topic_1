rule affbeefdebbefbcffdcaab_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "jooifwnpixcefxjfbl"
        $s3 = "ghmbtuvczexbcxzefe"
        $s4 = "rfmurtvjtxrkljnnuq"
        $s5 = "nuvqlniwkkbaloxilv"
        $s6 = "a\":z`K{F/*"
        $s7 = "_CorExeMain"
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "ThreadStaticAttribute"
        $s11 = "FileDescription"
        $s12 = "InitializeComponent"
        $s13 = "awhwvockljissdwkaa"
        $s14 = "fxqaeqiuacgzqndeec"
        $s15 = "klzcgebzmutbcbmzwa"
        $s16 = "zswossgxoqoymzilyu"
        $s17 = "ieczpclmvvuppucgyh"
        $s18 = "Synchronized"
        $s19 = "IAsyncResult"
        $s20 = "vk4?<xx)B=do"
condition:
    uint16(0) == 0x5a4d and filesize < 277KB and
    4 of them
}
    
