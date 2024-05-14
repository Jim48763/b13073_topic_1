rule ebbfaeadfbedbfaffd_dll {
strings:
        $s1 = "PrintDlgExW"
        $s2 = "VerInstallFileW"
        $s3 = "RemoveDirectoryA"
        $s4 = "winspool.drv"
        $s5 = "FreeIconList"
        $s6 = "OpenAs_RunDLLA"
        $s7 = "AddPrintProcessorA"
        $s8 = "SymInitialize"
        $s9 = "VirtualProtect"
        $s10 = "SetThreadToken"
        $s11 = ")T S@(XD\""
        $s12 = "GetClipRgn"
        $s13 = "ImagingEngine.dll"
        $s14 = "GetCurrentThread"
        $s15 = "SHGetValueW"
        $s16 = "version.dll"
        $s17 = "ImageUnload"
        $s18 = "A(>@\"lD\"JU"
        $s19 = "mid32Message"
        $s20 = "    <security>"
condition:
    uint16(0) == 0x5a4d and filesize < 258KB and
    4 of them
}
    
