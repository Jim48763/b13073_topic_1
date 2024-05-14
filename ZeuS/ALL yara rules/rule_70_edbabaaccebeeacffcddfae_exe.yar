rule edbabaaccebeeacffcddfae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "J\"o6>K*x 7"
        $s5 = "ytUH*6GpN^ "
        $s6 = "vU\"h_3^;]~"
        $s7 = "Ls=@AM(fb2;"
        $s8 = ">EFSgKA2|@{"
        $s9 = "zeN{OjRf9[ "
        $s10 = "DialogBoxParamA"
        $s11 = "IsWindowVisible"
        $s12 = "GetShortPathNameA"
        $s13 = "RemoveDirectoryA"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleA"
        $s16 = "SetCurrentDirectoryA"
        $s17 = "SHBrowseForFolderA"
        $s18 = "EnableWindow"
        $s19 = "Bc}v9QM#}CO3"
        $s20 = "SetWindowPos"
condition:
    uint16(0) == 0x5a4d and filesize < 1554KB and
    4 of them
}
    
