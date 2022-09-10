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
get-ipinfo.ps1 -ip 1.1.1.1 -json

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

function ValidateIP {  #IP Validation function
    param([string]$varIPValidate)
    [bool](($varIP -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" -and [bool]($varIPValidate -as [ipaddress]) -and !($varIPValidate -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)')))
}

if (($varIP -ne $null) -and (ValidateIP ($varIP) -eq $true)) {
    if ($json) { #check if the $json switch is set to true
        function write-host { #If $json = true, overide write-host to output nothing ($null)
            $null
        }
    } else {
        write-output "DEBUG: Optional json output flag not detected"
    }

    write-host "A valid routable IP was Supplied!" $varIPValidate
    
    write-host "Verifying if $varIP is currently responding to ICMP requests`n"
    if (Test-connection $varIP -count 1) {
        write-host "Success!`nPlease wait while we run a traceroute and ping test...`n"
        $varHops = (Test-NetConnection -TraceRoute -ComputerName $varIP).traceroute.count #Measure hops between script host and IP
        if ($PSVersionTable.PSVersion.major -gt "5") { #Workaround for changes in Test-Connection sytax post Powershell Version 5.1
            $varPingProperty = "Latency"
        } else {
            $varPingProperty = "ResponseTime"
        }
        $varPingAvg = ((Test-Connection $varIP -count 10).$varPingProperty | Measure-Object -Average).Average #measure ICMP latency 10 times
            
            
        write-host "There are a total of $varHops hops between this host ($env:computername) and the supplied IP $varIP."
        write-host "The average packet latency is $varPingAvg ms.`n"

    } else {
        Write-host "Error! We were not able to reach" $varIP
    }

    $header = @{"Accept" = "application/xml" }
    $varWhois = Invoke-RestMethod -Method Get "http://ip-api.com/json/$varIP" -Headers $header
    if (($varWhois.status -eq "success") -and ($varWhois.query -eq $varIP)) {
        $varWhoisLocation = $varWhois.City + ", " + $varWhois.Region + ", " + $varWhois.country
        $varGeoWeather = Invoke-RestMethod -Method Get -Uri ("http://api.weatherapi.com/v1/current.json?key=c90129e9d8c843869b350836221009&q=" + $varWhoisLocation) -Headers $header
        $varGeoLocalTime24 = ($varGeoWeather.location.localtime).Split(' ')[1]
        $varSplit = (([datetime]::ParseExact($varGeoLocalTime24, 'HH:mm', $null)).ToString()).Split(" ")
        $varGeoLocalTime12 = [string]$varSplit[1..($varSplit.count - 1)]

        write-host "The IP $varIP is:"
        write-host "    Owned by:" $varWhois.org
        write-host "    Belongs to the ASN:" ($varWhois.as).Split(' ')[0] "owned by"(($varWhois.as) -split ' ', 2)[-1]
        write-host "    Has a recorded ISP of:" $varWhois.isp
        write-host "    Geo-located to the general area of:" $varWhoisLocation"`n"
        write-host "Currently in" $varWhois.City "it is $varGeoLocalTime12 localtime, with weather conditions of:"
        write-host "   "$varGeoWeather.current.temp_f "degrees fahrenheit and"$varGeoWeather.current.condition.text""
        write-host "    A humidity of"$varGeoWeather.current.humidity "%"
        write-host "    A Windspeed of"$varGeoWeather.current.wind_mph"mph"
    } else {
        Write-host "There was a problem querying Whois Information"
        write-host "The returned response was: " $varWhois
    }
        
    if ($json) { #IF Json script parameter is set to true
        $varjsondata = [PSCustomObject]@{
            IPAddress    = "$($varIP)"
            Network_Tests  = @(
                @{
                    Query  = "Number of hops from $($env:computername) to $($varIP)."
                    Result = "$($varHops)"
                },
                @{
                    Query  = "Average latency of 10 ICMP packets to $($varIP) in milliseconds"
                    Result = "$($varPingAvg)"
                }
            )
            IP_Whois     = @(
                @{
                    Query  = "Netblock owner, ASN, ASN owner, and ISP"
                    Result = @{
                        Netblock_Owner = "$($varWhois.org)"
                        ASN            = "$(($varWhois.as).Split(' ')[0])"
                        ASN_Owner      = "$((($varWhois.as) -split ' ',2)[-1])"
                        ISP            = "$($varWhois.isp)"
                    }
                }   
            )
            IPGeoLocation = @(
                @{
                    Query  = "IP GeoLocation data"
                    Result = @{
                        City    = "$($varWhois.City)"
                        Region  = "$($varWhois.region)"
                        Country = "$($varWhois.country)"
                    }
                }
            )
            Weather      = @(
                @{
                    Query  = "Local weather Temperature and Humidity"
                    Result = @{
                        Temperature_c = "$($varGeoWeather.current.temp_c)"
                        Temperature_f = "$($varGeoWeather.current.temp_f)"
                        Humidity      = "$($varGeoWeather.current.humidity)"
                        Windspeed     = "$($varGeoWeather.current.wind_mph)"
                        Condition     = "$($varGeoWeather.current.condition.text)"

                    }
                }
            )
            Date_Time    = @(
                @{
                    Query  = "Local date and time"
                    Result = @{
                        Time_24_HHmm    = "$($varGeoLocalTime24)"
                        Time_12_hhmm_tt = "$($varGeoLocalTime12)"
                        Date_yyyy_mm_dd = "$(($varGeoWeather.location.localtime).Split(' ')[0])"
                        TimeZone_ID     = "$($varGeoWeather.location.tz_id)"
                    }
                }
            )
        }
        ConvertTo-Json -InputObject $varjsondata -Depth 3   #Output json data
        Remove-Item -Path Function:\write-host  #Cleanup write-host output disable trick
    }
    exit 0
    
} else {  #Detailed input validation error reporting
    if (!($varIP -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")) { #Check if IP is valid
        Write-host "Error! You provided an invalid IP Address! `nYou provided: $varIP"
    } elseif ($varIP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') { #Check if IP not a private non-routable
        Write-host "Error! You provided an non internet-routable ip address! `nYou provided: $varIP"
    } else {
        write-host "Error! You provided an IP address of $varIP that was not able to be validated!"
    }
    exit 1
}
