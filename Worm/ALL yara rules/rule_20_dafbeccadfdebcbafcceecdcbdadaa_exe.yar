rule dafbeccadfdebcbafcceecdcbdadaa_exe {
strings:
        $s1 = "\\drpreinject.dll"
        $s2 = "follow_systemwide"
        $s3 = "persist_lock_file"
        $s4 = "english-caribbean"
        $s5 = "vista_inject_at_create_process"
        $s6 = "switch_to_os_at_vmm_reset_limit"
        $s7 = "unsafe_ignore_eflags"
        $s8 = "detect_dangling_fcache"
        $s9 = "Runtime Error!"
        $s10 = "private_bb_ibl_targets_init"
        $s11 = "heap_commit_increment"
        $s12 = "SetConsoleCtrlHandler"
        $s13 = "unsafe_freeze_elide_sole_ubr"
        $s14 = "fast_client_decode"
        $s15 = "coarse_htable_load"
        $s16 = "ProductName"
        $s17 = "LC_MONETARY"
        $s18 = "IAT_convert"
        $s19 = "VarFileInfo"
        $s20 = "reset_at_switch_to_os_at_vmm_limit"
condition:
    uint16(0) == 0x5a4d and filesize < 484KB and
    4 of them
}
    
