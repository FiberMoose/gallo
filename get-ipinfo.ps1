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
    if (!(ValidateIP ($varIP))) {
        write-host "A valid routable IP was Supplied!" $varIP
        write-host "Please wait while we run a traceroute and ping test...`n"
        if (Test-connection $varIP -count 1) {
            $varHops = (Test-NetConnection -TraceRoute -ComputerName $varIP).traceroute.count
            $varPing = (Test-Connection $varIP -count 10).ResponseTime | Measure-Object -Average
            $varPingAvg = $varPing.Average

            write-host "There are a total of $varHops hops between this host ($env:computername) and the supplied IP $varIP."
            write-host "The average packet latency is $varPingAvg ms.`n"

        } else {
            Write-host "Error! We were not able to reach" $varIP
        }

        $header = @{"Accept" = "application/xml" }
        $varWhois = Invoke-RestMethod -Method Get "http://ip-api.com/json/$varIP" -Headers $header
        if (($varWhois.status -eq "success") -and ($varWhois.query -eq $varIP)) {
            $varWhoisLocation = $varWhois.City + ", " + $varWhois.Region + ", " + $varWhois.country
            $varGeoWeather = Invoke-RestMethod -Method Get -Uri ("http://api.weatherapi.com/v1/current.json?key=8ec40ca2e0114558af2164545202809&q=" + $varWhoisLocation) -Headers $header
            $varGeoLocalTime24 = ($varGeoWeather.location.localtime).Split(' ')[1]
            $varSplit = (([datetime]::ParseExact($varGeoLocalTime24, 'HH:mm', $null)).ToString()).Split(" ")
            $varGeoLocalTime12 = [string]$varSplit[1..($varSplit.count-1)]

            write-host "The IP $varIP is:"
            write-host "    Owned by:" $varWhois.org
            write-host "    Belongs to the AS Handle:" ($varWhois.as).Split(' ')[0] "owned by"(($varWhois.as) -split ' ',2)[-1]
            write-host "    Has a recorded ISP of:" $varWhois.isp
            write-host "    Geo-located to the general area of:" $varWhoisLocation
            write-host "`nCurrently in" $varWhois.City "it is $varGeoLocalTime12 localtime, with weather conditions of" $varGeoWeather.current.temp_f "degrees fahrenheit, and a humidity of"$varGeoWeather.current.humidity "%."
        } else {
            Write-host "There was a problem querying Whois Information"
            write-host "The returned response was: " $varWhois
        }

    } else {
        Write-host "ERROR! An invalid IP Address has been provided." -ForegroundColor red
    }
} else { 
    Write-host "ERROR! NO IP Address has been provided. `nPlease supply an IP through script parameter or when prompted." -ForegroundColor red
    #exit 1      #Commented out for testing
}
