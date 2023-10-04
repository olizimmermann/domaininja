rule TestDomain2
{   
    strings:
        $domain = /[A-z0-9]{3}\.[a-z]+/
    condition:
        any of them
}