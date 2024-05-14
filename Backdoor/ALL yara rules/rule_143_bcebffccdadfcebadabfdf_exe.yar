rule bcebffccdadfcebadabfdf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "e4x5yl10inb"
        $s4 = "_CorExeMain"
        $s5 = "AES_Decrypt"
        $s6 = "ernUfFoGWyg"
        $s7 = "VarFileInfo"
        $s8 = "T9w*XihasIq"
        $s9 = "FileDescription"
        $s10 = "Stub.Program"
        $s11 = "System.Resources"
        $s12 = "CallSiteBinder"
        $s13 = "$$method0x6000005-1"
        $s14 = "ResourceManager"
        $s15 = "InitializeArray"
        $s16 = "C<(%X9E/\""
        $s17 = "Y4=Q]<Fr01"
        $s18 = "8DdWt2`&{:"
        $s19 = "[2@B9WA5/D"
        $s20 = "*#Ox;y[*S$c"
condition:
    uint16(0) == 0x5a4d and filesize < 572KB and
    4 of them
}
    
