rule fcbdfaeaadfdcdbdfdbedeeadbfd_vbs {
strings:
        $s1 = "VJsyKMoK=\"7.42.B3.92.56.57.27.47.42.C2.C6.C6.57.E6.42.82.56.57.C6.16.65.47.56.35.E2.92.72.36.96.47.16.47.72.B2.72.35.C2.36.96.C6.72.B2.92.72.26.57.05.72.C2.72.04.04.04.72.82.56.36.16.C6.07.56.27.E2.72.04.04.04.E6.F6.E4.72.C2.72.46.56.C6.96.72.B2.72.16.64.47.96.E6.72.B2.72.94.96.72.B2.72.37.D6.72.B2.72.16.72.82.46.C6.56.96.64.47.56.74.E2.92.72.37.C6.96.47.55.72.B2.72.96.37.72.B2.72.D6.72.B2.72.14.E2.E6.72.B2.72.F6.96.47.16.72.B2.72.D6.F6.47.57.14.E2.72.B2.72.47.E6.56.72.B2.72.D6.56.76.72.B2.72.16.E6.16.D4.72.B2.72.E2.D6.56.47.37.72.B2.72.97.35.72.82.56.07.97.45.47.56.74.E2.97.C6.26.D6.56.37.37.14.E2.D5.66.56.25.B5.B3.76.66.63.53.47.42.02.D3.02.C6.F6.36.F6.47.F6.27.05.97.47.96.27.57.36.56.35.A3.A3.D5.27.56.76.16.E6.16.D4.47.E6.96.F6.05.56.36.96.67.27.56.35.E2.47.56.E4.E2.D6.56.47.37.97.35.B5.B3.92.23.73.03.33.02.C2.D5.56.07.97.45.C6.F6.36.F6.47.F6.27.05.97.47.96.27.57.36.56.35.E2.47.56.E4.E2.D6.56.47.37.97.35.B5.82.47.36.56.A6.26.F4.F6.45.A3.A3.D5.D6.57.E6.54.B5.02.D3.02.76.66.63.53.47.42.B3.92.76.E6.96.07.42.82.02.C6.96.47.E6.57.02.D7.47.56.96.57.15.D2.02.13.02.47.E6.57.F6.36.D2.02.D6.F6.36.E2.56.C6.76.F6.F6.76.02.07.D6.F6.36.D2.02.E6.F6.96.47.36.56.E6.E6.F6.36.D2.47.37.56.47.02.D3.02.76.E6.96.07.42.B7.02.F6.46'=lzkctqcIzMSoEnfsaEqF$;\""
        $s2 = "for i=999-998 to str1"
        $s3 = "End Function"
        $s4 = "End Sub"
        $s5 = "end if"
condition:
    uint16(0) == 0x5a4d and filesize < 10KB and
    4 of them
}
    
