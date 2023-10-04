rule TestDomain
{   
    strings:
        $domain= /[A-z0-9]+\.[a-z]+\.[a-z]+/
        $domain2 = /[A-z0-9]{4}\.[a-z]+/
    condition:
        any of them
}