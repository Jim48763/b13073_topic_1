rule efecacbebceaaeedabbcecedeff_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = ":)nJ{f'S#_9"
        $s4 = "rPF nZ\"Ii5"
        $s5 = "_CorExeMain"
        $s6 = "AES_Decrypt"
        $s7 = "lwoui4p0aq5"
        $s8 = "VarFileInfo"
        $s9 = "Vv}Gaqn^OuM"
        $s10 = "FileDescription"
        $s11 = "Stub.Program"
        $s12 = "System.Resources"
        $s13 = "CallSiteBinder"
        $s14 = "$$method0x6000005-1"
        $s15 = "ResourceManager"
        $s16 = "InitializeArray"
        $s17 = "i,/mZ\"ckq"
        $s18 = "/T( \":c*K"
        $s19 = "CmxDFTd~q9"
        $s20 = ",a?qewfo(y"
condition:
    uint16(0) == 0x5a4d and filesize < 552KB and
    4 of them
}
    
