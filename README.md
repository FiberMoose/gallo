# (RPA SaaS Interview challenge)aaS
This is a github repo setup as part of an interview challenge at a poultry-themed startup.

# Usage
### 1. Basic interactive usage
__Note:__ If the -ip parameter is not provided, you will be prompted for it at execution

From a command prompt:
```
C:\Temp\>powershell -ep bypass -c ". .\get-ipinfo.ps1 -ip 1.1.1.1"
```

From a PowerShell prompt:
```
PS C:\Temp\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\Temp\> . .\get-ipinfo.ps1 -ip 1.1.1.1
```

### 2. Json-only output mode

From a command prompt:
```
C:\Temp\>powershell -ep bypass -c ". .\get-ipinfo.ps1 -ip 1.1.1.1 -json"
```

From a PowerShell prompt:
```
PS C:\Temp\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\Temp\> . .\get-ipinfo.ps1 -ip 1.1.1.1 -json
```

### 3. Tests
__Download the script:__
```
powershell -exec bypass -c "Invoke-WebRequest https://raw.githubusercontent.com/FiberMoose/gallo/main/get-ipinfo.ps1 -OutFile $env:TEMP\get-ipinfo.ps1"
```
__Test Normal expected Behavior:__
```
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1"   #Test No parameter
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 1.1.1.1"   #Test ip parameter with valid public ipv4
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 8.8.8.8 -json"   #Test valid public ipv4 with json
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 2600:3c01::f03c:91ff:fe93:48f8"   #Test valid public ipv6
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 2a03:2880:f12f:83:face:b00c::25de -json"   #Test valid public ipv6 with json
```
__Test Validating public IP Validation:__
```
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 172.16.1.1"   #Test with private ipv4 
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 192.168.1.1 -json"   #Test valid private ipv4 with json
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip FD00::4:120"   #Test with private ipv6
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip FDC8:BF8B:E62C:ABCD:1111:2222:3333:4444 -json"   #Test valid private ipv6 with json
```
__Test Invalid IPs:__
```
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 257.66.11.2"   #Test with Invalid ipv4 
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip abc.def.123.456 -json"   #Test invalid private ipv4 with json
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip fe80:2030:31:24"   #Test with invalid ipv6
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip FAC8:BF8B:E62K:ABCD2222:3333 -json"   #Test invalid private ipv6 with json
```
__Test known IPs with ICMP Response disabled:__
```
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 4.4.4.4"   #Test ip parameter with valid public ipv4, rejecting pings 
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 13.82.28.61 -json"   #Test valid public ipv4 with json, rejecting pings
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 2001:4860:4860::8888"   #Test valid public ipv6, rejecting pings
powershell -exec bypass -c ". $env:TEMP\get-ipinfo.ps1 -ip 2600:1f18:631e:2f80:77e5:13a7:6533:7584 -json"   #Test valid public ipv6 with json, rejecting pings
```

