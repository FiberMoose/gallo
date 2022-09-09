<#
.SYNOPSIS 
Accepts an IP Address with validation, then queries IP Information.

.DESCRIPTION
Accepts an IP Address with validation, then:
Counts hops between the supplied IP and script host
Measures average latency between IP and script host
Queries Whois, geoIP, ASN info, as well as enviormental information local to the IP GeoIP location.

.PARAMETER IP
Specifies the IP Address to query

.EXAMPLE 
get-ipinfo.ps1 -ip 1.1.1.1

.LINK
Github Repo:  https://github.com/fibermoose/gallo/
#>

param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'Please provide a valid internet routable IP Address to query')]
    [Alias("IP")]
    [string]${IP Address}
)
$varIP = ${IP Address}


#TODO: everything

