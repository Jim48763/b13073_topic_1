rule acbbbcebdbadfadfcebf_exe {
strings:
        $s1 = "l?JP5]*'Ce-"
        $s2 = "*V_W\"R4p,E"
        $s3 = "T=FGCr0SKL%"
        $s4 = "|9xM1&(+?RE"
        $s5 = "LoadStringW"
        $s6 = "ProgramFilesDir"
        $s7 = "IsWindowVisible"
        $s8 = "DialogBoxParamW"
        $s9 = "Not enough memory"
        $s10 = "GetModuleHandleW"
        $s11 = "DispatchMessageW"
        $s12 = "CRC failed in %s"
        $s13 = "CreateCompatibleBitmap"
        $s14 = "GetCurrentDirectoryW"
        $s15 = "SHBrowseForFolderW"
        $s16 = "OLEAUT32.dll"
        $s17 = "SetEndOfFile"
        $s18 = ">MIuHU\"x1Uh"
        $s19 = "</trustInfo>"
        $s20 = "GETPASSWORD1"
condition:
    uint16(0) == 0x5a4d and filesize < 1975KB and
    4 of them
}
    
