rule TestDomain2
{   
    strings:
        $domain = /^[A-z0-9]{3}\.[a-z]{2}$/
    condition:
        any of them
}