rule defdbbfadcffdeacd_exe {
strings:
        $s1 = "z1rqrEjxrIqjtjJRrg7"
        $s2 = "STAThreadAttribute"
        $s3 = "]q+GlAr!a(~"
        $s4 = "Rb7wOkE:n+c"
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "7wZ+C?3~\"#"
        $s9 = "FileDescription"
        $s10 = "QQgI44J44Nci4utkkYy"
        $s11 = "AssemblyTitleAttribute"
        $s12 = "]cp6g g?xv#("
        $s13 = "Synchronized"
        $s14 = "System.Resources"
        $s15 = "Customers.xml"
        $s16 = "customer_list"
        $s17 = "AutoScaleMode"
        $s18 = "    </application>"
        $s19 = "IiCLOHMBICBdi0XiNi"
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 589KB and
    4 of them
}
    
