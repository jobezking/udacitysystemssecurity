rule NPA_URL {
        meta:
                Author = "@jobking"
                Description = "the rule detects Command & control server of the National Peace agency URLs"
        strings:
                $url1 = "http://darkl0rd.com:7758/SSH-T"
                $url2 = "http://darkl0rd.com:7758/SSH-One"
        condition:
                any of them

}

