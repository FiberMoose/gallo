# (RPA SaaS Interview challenge)aaS
This is a github repo setup as part of an interview challenge at a poultry-based startup.

# Usage
### 1. Basic usage
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

### 2. Json export mode

From a command prompt:
```
C:\Temp\>powershell -ep bypass -c ". .\get-ipinfo.ps1 -ip 1.1.1.1 -json"
```

From a PowerShell prompt:
```
PS C:\Temp\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\Temp\> . .\get-ipinfo.ps1 -ip 1.1.1.1 -json
```
