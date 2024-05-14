rule debfccfeabfcdaefadadb_ps {
strings:
        $s1 = "    # open logger file in Notepad"
        $s2 = "          # get keyboard state for virtual keys"
        $s3 = "  # create output file"
        $s4 = "        if ($state -eq -32767) {"
        $s5 = "Start-KeyLogger"
        $s6 = "          # translate virtual key"
        $s7 = "          # translate scan code to real code"
        $s8 = "        # get current key state"
        $s9 = "            # add key to logger file"
        $s10 = "        # is key pressed?"
        $s11 = "    $Runner = 0"
        $s12 = "$RunTimeP = 1                       # Time in minutes"
        $s13 = "          if ($success) "
        $s14 = "  finally"
        $s15 = "exit 1"
        $s16 = "          {"
        $s17 = "############################"
        $s18 = "  try"
        $s19 = "    }"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
