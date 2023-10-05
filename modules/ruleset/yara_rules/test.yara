rule MercedesBenzTypoSquatting
{   
    strings:
        $domain= /^mercedes\-ben[^z]?\.com$/
        $domain2 = /^mercedesben[^z]?\.com$/
        $domain3 = /^mercedesbenz[^z]?\.com$/
        $domain4 = /^mercedesbenz[^z]?\.net$/
        $domain5 = /^mercedesbenz[^z]?\.org$/
        $domain6 = /^mercedesbenz[^z]?\.info$/
        $domain7 = /^mercedesbenz[^z]?\.biz$/
    condition:
        any of them
}