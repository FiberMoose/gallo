<#
.SYNOPSIS 
Accepts an IPv4 Address with validation, then queries IP Information.

.DESCRIPTION
Accepts an IPv4 Address with validation, then:
Counts hops between the supplied IP and script host
Measures average latency between IP and script host
Queries Whois, geoIP, ASN info, as well as weather information local to the IP GeoIP location.

.PARAMETER IP
Mandatory, Specifies the IP Address to query. 
If not provided, the script will prompt for it.
MANDATORY if using the json parameter.

.PARAMETER JSON
Optional, Directs all script output to json format, mutes human friendly console output
-IP Parameter MANDATORY when using the json switch

.EXAMPLE 
.\get-ipinfo.ps1 -ip 1.1.1.1

.EXAMPLE
.\get-ipinfo.ps1 -ip 1.1.1.1 -json

.LINK
Github Repo:  https://github.com/fibermoose/gallo/
#>

param (
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Please provide a valid internet routable IP Address to query")]
    [Alias("IP")]
    [string]${IP Address},

    [Parameter(Position = 1, Mandatory = $false)]
    [switch]$json
)
$varIP = ${IP Address}

$ErrorActionPreference = "silentlycontinue"

#Define IP Regex
$varIPv4PrivateRegex = "(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)"
$varIPv4ValidRegex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
$varIPv6ValidRegex = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
$varIPv6PrivateRegex = "(^::1$)|(^[fF][cCdD])" 


function ValidateIP {
    #IP Validation function
    param([string]$varIPValidate)
    [bool](((($varIP -match $varIPv4ValidRegex) -OR ($varIP -match $varIPv6ValidRegex)) -and (!($varIPValidate -Match $varIPv4PrivateRegex)) -and (!($varIPValidate -Match $varIPv6PrivateRegex))))
}

function ValidateIPDescriptive {
    #IP validation function with detailed error message
    param([string]$varIPValidate)
    if ($varIPValidate -Match $varIPv4PrivateRegex) {
        #Check if IP is a private non-routable ipv4
        "ERROR: Non-routable IPv4 Address provided."
    } elseif ($varIPValidate -Match $varIPv6PrivateRegex) {
        #Check if IP is a private non-routable ipv6
        "ERROR: Non-routable IPv6 Address provided."
    } elseif ((!($varIPValidate -match $varIPv4ValidRegex)) -and (!($varIPValidate -match $varIPv6ValidRegex))) {
        #Check if IP is a valid formatted IPv4 IP Address
        "ERROR: Invalid IP Address provided."
    } else {
        "ERROR: Invalid IP Address provided" 
    }
}
Function IPV6ValidRoutablecheck {
    param([string]$varIPValidate)
    [bool](($varIPValidate -Match $varIPv6ValidRegex) -and (!($varIPValidate -Match $varIPv6PrivateRegex))) 
    #Check if iP is an public IPv6 address
}

if (IPV6ValidRoutablecheck ($varIP)) {
    $varIPType = "IPv6"
} else {
    $varIPType = "IPv4"
}

if (($varIP -ne $null) -and (ValidateIP ($varIP) -eq $true)) {
    if (!($json)) {
        write-host "`nA valid routable $varIPType address was Supplied!" $varIPValidate
        if ($varIPType -eq "IPv6") {
            write-host "WARNING: IPV6 Addresses are not always reliably queried. Expect erratic behavior." -ForegroundColor yellow
        }
        write-host "`nVerifying if $varIP is currently responding to ICMP requests`n"
    }
    
    if (Test-connection $varIP -count 1) {
        if (!($json)) {
            write-host "Success!`nPlease wait while we run a traceroute and ping test...`n" -ForegroundColor green
        }
        $varHops = (Test-NetConnection -TraceRoute -ComputerName $varIP).traceroute.count #Measure hops between script host and IP
        if ($PSVersionTable.PSVersion.major -gt "5") {
            #Workaround for changes in Test-Connection sytax post Powershell Version 5.1
            $varPingProperty = "Latency"
        } else {
            $varPingProperty = "ResponseTime"
        }
        #Test-connection has problems with IPv6 on some systems. 
        $varPingAvg = ((Test-Connection $varIP -count 10).$varPingProperty | Measure-Object -Average).Average #measure ICMP latency 10 times
            
        if (!($json)) {    
            write-host "There are a total of $varHops hops between this host ($env:computername) and the supplied IP $varIP."
            write-host "The average packet latency is $varPingAvg ms.`n"
        }

    } else {
        if (!($json)) {
            Write-host "Error! We were not able to reach" $varIP "`n"-ForegroundColor red
            $varPingAvg = "Error: Ping failed"
            $varHops = "Error: Traceroute failed"
        }
        $varIPTestsError = $error[0].ToString()
    }

    $header = @{"Accept" = "application/xml" }
    $varWhois = Invoke-RestMethod -Method Get "http://ip-api.com/json/$varIP" -Headers $header
    $varWhoisLocation = $varWhois.City + ", " + $varWhois.Region + ", " + $varWhois.country
    $varGeoWeather = Invoke-RestMethod -Method Get -Uri ("http://api.weatherapi.com/v1/current.json?key=c90129e9d8c843869b350836221009&q=" + $varWhoisLocation) -Headers $header

    if ($varWhois.status -eq "success") {
        if (($varGeoWeather.current.temp_f -gt "0") -and ($varGeoWeather.location.name -contains $varWhois.City)) {
            $varGeoLocalTime24 = ([string]($varGeoWeather.location.localtime).Split(' ')[1].PadLeft(5, '0'))
            $varSplit = (([datetime]::ParseExact($varGeoLocalTime24, 'HH:mm', $null)).ToString()).Split(" ")
            $varGeoLocalTime12 = [string]$varSplit[1..($varSplit.count - 1)]
            if (!($json)) {
                write-host "The IP $varIP is:"
                write-host "    Owned by:" $varWhois.org
                write-host "    Belongs to the ASN:" ($varWhois.as).Split(' ')[0] "owned by"(($varWhois.as) -split ' ', 2)[-1]
                write-host "    Has a recorded ISP of:" $varWhois.isp
                write-host "    Geo-located to the general area of:" $varWhoisLocation"`n"
                write-host "Currently in" $varWhois.City "it is $varGeoLocalTime12 localtime, with weather conditions of:"
                write-host "   "$varGeoWeather.current.temp_f "degrees fahrenheit and"$varGeoWeather.current.condition.text""
                write-host "    A humidity of"$varGeoWeather.current.humidity "%"
                write-host "    A Windspeed of"$varGeoWeather.current.wind_mph"mph"
            }
        } else {
            if (!($json)) {
                Write-host "There was a problem querying Weather and Time Information" -ForegroundColor red
                write-host "The returned response was: `n" ($varGeoWeather | convertto-json)
            }
            $varWeatherError = "ERROR: Weather query failed."
        }
    } else {
        if (!($json)) {
            Write-host "There was a problem querying Whois Information" -ForegroundColor red
            write-host "The returned response was: `n" ($varWhois | convertto-json)
        }
        $varWhoisError = "ERROR: Whois query failed."
    }


    if ($json) {
        #IF Json script parameter is set to true
        $varjsondata = @{
            'IPAddress'     = "$($varIP)"
            'Network_Tests' = @{
                'Hops'        = "$($varHops)"
                'Latency_avg' = "$($varPingAvg)"
                'ERROR'       = "$($varIPTestsError)"
            }
            'IP_Whois'      = @{
                'Netblock_Owner' = "$($varWhois.org)"
                'ASN'            = "$(($varWhois.as).Split(' ')[0])"
                'ASN_Owner'      = "$((($varWhois.as) -split ' ',2)[-1])"
                'ISP'            = "$($varWhois.isp)"
                'ERROR'          = "$($varWhoisError)"
            }
            'IPGeoLocation' = @{
                'City'    = "$($varWhois.City)"
                'Region'  = "$($varWhois.region)"
                'Country' = "$($varWhois.country)"
            }
            'Weather'       = @{
                'Temperature_c' = "$($varGeoWeather.current.temp_c)"
                'Temperature_f' = "$($varGeoWeather.current.temp_f)"
                'Humidity'      = "$($varGeoWeather.current.humidity)"
                'Windspeed'     = "$($varGeoWeather.current.wind_mph)"
                'Condition'     = "$($varGeoWeather.current.condition.text)"
                'ERROR'         = "$($varWeatherError)"
            }
            'Date_Time'     = @{
                'Time_24_HHmm'    = "$($varGeoLocalTime24)"
                'Time_12_hhmm_tt' = "$($varGeoLocalTime12)"
                'Date_yyyy_mm_dd' = "$(($varGeoWeather.location.localtime).Split(' ')[0])"
                'TimeZone_ID'     = "$($varGeoWeather.location.tz_id)"
            }
        }
        ConvertTo-Json -InputObject $varjsondata -Depth 2   #Output json data
        Remove-Item -Path Function:\write-host  #Cleanup write-host output disable trick
    }
    #exit 0
    
} elseif ($json) {
    #error output if IP provided is invalid and json switch set
    $varjsondata = @{
        'IPAddress' = "$($varIP)"
        'ERROR'     = "$(ValidateIPDescriptive ($varIP))"
    }
    ConvertTo-Json -InputObject $varjsondata

} else {
    #Detailed input validation error reporting
    ValidateIPDescriptive ($varIP)
    #exit 1
}
