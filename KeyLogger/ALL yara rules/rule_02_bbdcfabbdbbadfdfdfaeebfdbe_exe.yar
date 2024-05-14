rule bbdcfabbdbbadfdfdfaeebfdbe_exe {
strings:
        $s1 = "PlaceCommandProcessor"
        $s2 = "008%0c%fd%ff%ff%00*%00v%2b%09(%03l%15%3f%14%16%9a%26%16-%f9%"
        $s3 = "c3%a1%d1%f6%9a%7c%d6%f9%eeP%b4%b4v%8cQ%dd%18%ca%da%a4%d9%cf%a4e%bci%ab%bf%d9%9e%"
        $s4 = "2b%09(%80S%02%3b%14%16%9a%26%16-%f9s%8b%"
        $s5 = "c0%07%bfO%d2A%fe%0c0%00vl%5b%fe%0c0%00vlXm%fe%0e%12%00+%1c%fa%ab%"
        $s6 = "set_ForegroundColor"
        $s7 = "RuntimeHelpers"
        $s8 = "a6%059%02%02%10%b4%05!%03%e6%18%bd%02!%03%ee%18%bd%02!%03%f5%18%c6%059%02%05%19%cc%059%02%0b%197%00)%02%f3%11%d4%05%19%01%88%19%ed%05Y%03%b5%19%f4%059%02%d7%19%"
        $s9 = "STAThreadAttribute"
        $s10 = "OrangeGhost"
        $s11 = "_CorExeMain"
        $s12 = "op_Equality"
        $s13 = "VarFileInfo"
        $s14 = "~#ir)ms?\"4"
        $s15 = "ProductName"
        $s16 = "DefaultMemberAttribute"
        $s17 = "PacmanSimulator"
        $s18 = "FileDescription"
        $s19 = "set_CursorVisible"
        $s20 = "02%02%8ei%17Y%91%1fpa%0b+%07%"
condition:
    uint16(0) == 0x5a4d and filesize < 811KB and
    4 of them
}
    
