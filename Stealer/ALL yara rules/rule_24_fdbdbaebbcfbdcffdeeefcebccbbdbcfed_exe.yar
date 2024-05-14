rule fdbdbaebbcfbdcffdeeefcebccbbdbcfed_exe {
strings:
        $s1 = "</assembly>P"
        $s2 = "VirtualProtect"
        $s3 = "SHLWAPI.dll"
        $s4 = "ExitProcess"
        $s5 = "COMCTL32.dll"
        $s6 = "GetProcAddress"
        $s7 = "ShellExecuteExA"
        $s8 = "CoInitialize"
        $s9 = "VirtualAlloc"
        $s10 = "        language=\"*\" />"
        $s11 = "InitCommonControls"
        $s12 = "SetBkColor"
        $s13 = "MSVCRT.dll"
        $s14 = "GN#<-#%C?A"
        $s15 = "SHELL32.dll"
        $s16 = "VirtualFree"
        $s17 = "LoadLibraryA"
        $s18 = "  <dependency>"
        $s19 = "KERNEL32.DLL"
        $s20 = "8!SDWj g@"
condition:
    uint16(0) == 0x5a4d and filesize < 215KB and
    4 of them
}
    
