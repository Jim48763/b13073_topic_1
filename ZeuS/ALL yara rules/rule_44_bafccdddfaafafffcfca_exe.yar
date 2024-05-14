rule bafccdddfaafafffcfca_exe {
strings:
        $s1 = "GetModuleFileName"
        $s2 = "/TN \"Update\\"
        $s3 = "VQQqQMIYzBhTtF"
        $s4 = "A)Rg{kfotState"
        $s5 = "VirtualAllocEx"
        $s6 = "System.ComponentMo"
        $s7 = "qEe@Cg>znM="
        $s8 = "aNEZFIrWJfK"
        $s9 = "a2rSJ4oV7Oe"
        $s10 = "NrgBoxStyle"
        $s11 = "s{y~EUX`)^8"
        $s12 = " pwoNs9A)Ze"
        $s13 = "a0x5gTZw2JV"
        $s14 = "ThreadStaticAttribute"
        $s15 = ".]oHppsentProcess"
        $s16 = "Central Anatolia1"
        $s17 = "ReadProcessMemory"
        $s18 = "InitializeComponent"
        $s19 = "uthor>  </Re"
        $s20 = "ERID]</UserI"
condition:
    uint16(0) == 0x5a4d and filesize < 234KB and
    4 of them
}
    
