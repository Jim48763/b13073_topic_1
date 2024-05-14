rule fdddcacafffbbccfbafda_exe {
strings:
        $s1 = "ProductName"
        $s2 = "^9,Ie0~2(>f"
        $s3 = "DeviceIoControl"
        $s4 = "TerminateProcess"
        $s5 = "SetFilePointerEx"
        $s6 = "GetComputerNameW"
        $s7 = "GetTickCount"
        $s8 = "@Vu!GVb|*W:p"
        $s9 = "{X)Cz][-61[J"
        $s10 = ">f&;c$3(Y,,M"
        $s11 = "v][V&@6++7LT"
        $s12 = "_!}j-V)\\!k<A"
        $s13 = "ControlService"
        $s14 = "OpenSCManagerA"
        $s15 = "Opera Software"
        $s16 = "    </security>"
        $s17 = "GetFileAttributesW"
        $s18 = "GetDriveTypeW"
        $s19 = "RegOpenKeyExW"
        $s20 = ".Oor#\"lE\\i?"
condition:
    uint16(0) == 0x5a4d and filesize < 803KB and
    4 of them
}
    
