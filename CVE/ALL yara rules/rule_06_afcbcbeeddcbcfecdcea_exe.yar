rule afcbcbeeddcbcfecdcea_exe {
strings:
        $s1 = "0@.eh_fram"
        $s2 = "ATPQRSUVWH"
        $s3 = "ntoskrnl.exe"
        $s4 = "ZwCreateEvent"
        $s5 = "dump.exe 2"
        $s6 = "_^][ZYXA\\A"
        $s7 = "kernel32.dll"
        $s8 = "c:\\ok_0000"
        $s9 = "AQAPRQVH1"
        $s10 = "AXAX^YZAXAY"
        $s11 = "ntdll.dll"
        $s12 = "0`.data"
        $s13 = "0@.bss"
        $s14 = ".idata"
        $s15 = "xKcC!"
        $s16 = "D$@H1"
        $s17 = "XAYZH"
        $s18 = "memset"
        $s19 = ".text"
        $s20 = "NN!!!!"
condition:
    uint16(0) == 0x5a4d and filesize < 116KB and
    4 of them
}
    
