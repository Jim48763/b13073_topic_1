rule eeeffddabdbdddcefbaeefbfbb_exe {
strings:
        $s1 = "YgLYYbLYVGmwDRtqX"
        $s2 = "ManagementBaseObject"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "get_ProcessorCount"
        $s5 = "_CorExeMain"
        $s6 = "SocketFlags"
        $s7 = "op_Equality"
        $s8 = "VarFileInfo"
        $s9 = "ComputeHash"
        $s10 = "set_ErrorDialog"
        $s11 = "IsWindowVisible"
        $s12 = "timeout 3 > NUL"
        $s13 = "otUWNRLOOOhkmpW"
        $s14 = "FileDescription"
        $s15 = "ToShortDateString"
        $s16 = "mBjllbEQlYrTYiQHj"
        $s17 = "FFLFRzkSCIIygLKi"
        $s18 = "vMFhHFBstSGu"
        $s19 = "Dictionary`2"
        $s20 = "ComputerInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 51KB and
    4 of them
}
    
