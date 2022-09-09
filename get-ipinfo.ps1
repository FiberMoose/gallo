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


function ValidateIP ($varIP) {
    if ($varIP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and [bool]($varIP -as [ipaddress]) -and !($varIP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)')) {
        $true | out-null
    } else {
        if (!($varIP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")) {
            write-host "ERROR! You provided an invalid IP Address! `nYou provided: "$varIP
        } elseif ($varIP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') {
            write-host "ERROR! You provided an non internet-routable ip address! `nYou provided: "$varIP
        }
        $false | out-null
        #exit 1    #Commented out for testing
    }
}

if ($varIP -ne $null) {
    if (ValidateIP ($varIP)) {
        $varHops = (Test-NetConnection -TraceRoute -ComputerName $varIP).traceroute.count
        $varPing = (Test-Connection $varIP -count 10).ResponseTime | Measure-Object -Average
        $varPingAvg = $varPing.Average

        write-host "Network tests indicate there are $varHops network hops with an average packet latency of $varPingAvg ms between this host and the Supplied IP $varIP"


    }
} else {
    Write-host "#####`nERROR! NO IP Address has been provided. `nPlease supply an IP through script parameter or when prompted.`n#####" -ForegroundColor red
    #exit 1      #Commented out for testing
}
