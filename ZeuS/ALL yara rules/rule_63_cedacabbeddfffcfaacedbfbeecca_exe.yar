rule cedacabbeddfffcfaacedbfbeecca_exe {
strings:
        $s1 = "Directory not empty"
        $s2 = "Runtime Error!"
        $s3 = "No child processes"
        $s4 = "F|DRBHPnNd,"
        $s5 = "X\"Y$:Joc/k"
        $s6 = "VarFileInfo"
        $s7 = "Mn^b-U+h9;7"
        $s8 = ":=u->AJ?v<D"
        $s9 = "GetClusterNetInterfaceState"
        $s10 = "FileDescription"
        $s11 = "Z/h),<B@B@BPA?A!"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "Operation not permitted"
        $s15 = "GetCurrentThreadId"
        $s16 = "No locks available"
        $s17 = "S%B#0!?--L+:"
        $s18 = "Invalid seek"
        $s19 = "&:$02V0L.\","
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 223KB and
    4 of them
}
    
