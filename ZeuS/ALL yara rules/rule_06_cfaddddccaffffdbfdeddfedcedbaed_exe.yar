rule cfaddddccaffffdbfdeddfedcedbaed_exe {
strings:
        $s1 = "aVc;{xUQWRSxWWgWG"
        $s2 = "tH8N:vu[]B="
        $s3 = "Jgm`bpatvWS"
        $s4 = "CKPx|kYS3~9"
        $s5 = ",2zvlhL9M<S"
        $s6 = "_NTqlRcyzwu"
        $s7 = "QDC76_2U8PK"
        $s8 = "1BHm}8V_Q7K"
        $s9 = "YiE9o0U;Okt"
        $s10 = "XeCm]jukiTo"
        $s11 = "bptWl_jHrad"
        $s12 = "#Po4xIy8HXL"
        $s13 = ")H:z6M}Omv8"
        $s14 = "-7y6;GQ:<`c"
        $s15 = "+2qTdm^I:Ja"
        $s16 = "{Bl^xycQDJf"
        $s17 = "*PnXxwWSYt}"
        $s18 = "Zw_YyIngM~i"
        $s19 = "/TBSms6]KMN"
        $s20 = "zlDX{MjJ_Ec"
condition:
    uint16(0) == 0x5a4d and filesize < 204KB and
    4 of them
}
    
