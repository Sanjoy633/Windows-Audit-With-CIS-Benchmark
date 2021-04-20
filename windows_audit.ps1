#Set-ExecutionPolicy RemoteSigned -force

#CSS codes
$header = @"
<title>Audit Report: $env:computername</title>
<style>

    .title {

        font-family: Arial, Helvetica, sans-serif;
        color: #4242f9;
        font-size: 34px;
		text-align: center;

    }
	h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #4242f9;
        font-size: 28px;

    }

    
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;

    }

    
    
   table {
		font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
		width: 100%;
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
    


    #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;

    }



    .StopStatus, .false {

        color: #ff0000;
    }
    
  
    .RunningStatus, .true {

        color: #008000;
    }




</style>
"@



#The command below will get the name of the computer
$ComputerName = "<h1>Computer name: $env:computername</h1>"

$Author = @"



'  :'######::'########:::::'###:::::'######:::::::::::::::::'##:::'##:
'  '##... ##: ##.... ##:::'## ##:::'##... ##:::::::::::::::: ##::'##::
'   ##:::..:: ##:::: ##::'##:. ##:: ##:::..::::::::::::::::: ##:'##:::
'   ##::::::: ##:::: ##:'##:::. ##: ##::::::::::'#######:::: #####::::
'   ##::::::: ##:::: ##: #########: ##::::::::::........:::: ##. ##:::
'   ##::: ##: ##:::: ##: ##.... ##: ##::: ##:::::::::::::::: ##:. ##::
'  . ######:: ########:: ##:::: ##:. ######::::::::::::::::: ##::. ##:
'  :......:::........:::..:::::..:::......::::::::::::::::::..::::..::
'  ::::::::::::::::SECURITY::::AUDIT:::SERVICES:::::::::::::::::::::::


"@
Write-Host $Author -ForegroundColor White -BackgroundColor Blue
Write-Host
Write-Host "Abhijit Chatterjee & Sanjoy Kanrar - CDAC Team  - sa-kol@cdac.in " -ForegroundColor Yellow

Write-Host "[?] Checking for administrative privileges .." -ForegroundColor DarkBlue
Start-Sleep -s 1
$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
if(!$isAdmin){
            
    Write-Warning  "[-] Some of the operations need administrative privileges.`n"
    Write-Warning  "[*] Please run the script using an administrative account.`n"
	Read-Host "Type any key to continue .."
	exit
}

Write-Host RETRIEVE CONFIGURATION. PLEASE WAIT... -ForegroundColor Yellow -BackgroundColor Black
Write-Host Please close all other windows until the retrieval is complete.
Write-Host
Start-Sleep -s 2



# Function to reverse SID from SecPol
Function Reverse-SID ($chaineSID) {

  $chaineSID = $chaineSID -creplace '^[^\\]*=', ''
  $chaineSID = $chaineSID.replace("*", "")
  $chaineSID = $chaineSID.replace(" ", "")
  $tableau = @()
  $tableau = $chaineSID.Split(",") 
  ForEach ($ligne in $tableau) { 
    $sid = $null
    if ($ligne -like "S-*") {
      if($reverseCommandExist -eq $true){
      $sid = Get-WSManInstance -ResourceURI "wmicimv2/Win32_SID" -SelectorSet @{SID="$ligne"}|Select-Object AccountName
      $sid = $sid.AccountName
      }else{
        $objSID = New-Object System.Security.Principal.SecurityIdentifier ("$ligne")
        $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
        $sid=$objUser.Value
      }
      #$outpuReverseSid += $sid + "|"
      $outpuReverseSid += $sid + ", "
    }else{
      #$outpuReverseSid += $ligne + "|"
      $outpuReverseSid += $ligne + ", "
    }
  }

  

  return $outpuReverseSid

}
# convert ComplianceOrNotHTML 
function ComplianceOrNotToHTML($flag) {
  if ($flag) {    
    return '<td class="true">Compliance</td>'
  }
  else {
    return '<td class="false">Non Compliance</td>'
  }
}
function ComplianceWriteHost($ComplianceName,$flag) {
  if ($flag) {    
    Write-Host "       [+] "$ComplianceName -ForegroundColor Green
  }
  else {
    Write-Host "       [-] "$ComplianceName -ForegroundColor Red
  }
}

# convert Stringarray to comma separated liste (String)
function StringArrayToList($StringArray) {
  if ($StringArray) {
    $Result = ""
    Foreach ($Value In $StringArray) {
      if ($Result -ne "") { $Result += "," }
      $Result += $Value
    }
    return $Result
  }
  else {
    return ""
  }
}

Function Get-HTMLDetail ($Heading, $Detail){
$Report = @"
<TABLE>
	<tr>
	<th width='25%'><b>$Heading</b></font></th>
	<td width='75%'>$($Detail)</td>
	</tr>
</TABLE>
"@
Return $Report
}

#The command below will get the name of the computer
$ToolDetails = @"
<div class='title'>WINDOWS AUDIT TOOLS</div>
<h2><center>SECURITY AUDIT SERVICES, CDAC</center></h2>

<hr>

"@


#get the date
$Date = Get-Date -U %d%m%Y

$nomfichier = "audit" + $date + ".txt"

Write-Host "       [+] Create Audit directory " -ForegroundColor DarkGreen

$nomdossier = "CDAC_Audit_CONF_" + $date
#Delete the folder if exists
Remove-Item $nomdossier -Recurse -ErrorAction Ignore
New-Item -ItemType Directory -Name $nomdossier | Out-Null
Set-Location $nomdossier
#Get intel from the machine

$OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory, NumberOfUsers, BootDevice

$OSversion = $OSInfo.Caption
$OSName = $OSInfo.CSName
$OSArchi = $OSInfo.OSArchitecture


#Put it in a file
Write-Host "       [+] Take Server Information " -ForegroundColor DarkGreen
"#########INFO MACHINE#########" > $nomfichier
"Os version: $OSversion " >> $nomfichier
"Machine name : $OSName " >> $nomfichier
"Machine architecture : $OSArchi" >> $nomfichier
#Start testing
"#########AUDIT MACHINE#########" >> $nomfichier
$indextest = 1
$chaine = $null
$traitement = $null


#Take file important for analysis 
Write-Host "       [+] Take File to analyse `n" -ForegroundColor DarkGreen
$seceditfile = "./secpol" + "-" + "$OSName" + ".cfg"
secedit /export /cfg $seceditfile | out-null
$gpofile = "./gpo" + "-" + "$OSName" + ".txt"
gpresult /r /V > $gpofile | out-null
$gpofile = "./gpo" + "-" + "$OSName" + ".html"
gpresult /h $gpofile /f | out-null
#Second command in case of emergency


$auditconfigfile = "./auditpolicy" + "-" + "$OSName" + ".txt"

auditpol.exe /get /Category:* > $auditconfigfile | out-null



#The command below will get the Operating System information, convert the result to HTML code as table and store it to a variable
$OSinfo = Get-CimInstance -Class Win32_OperatingSystem | ConvertTo-Html -As List -Property Version,Caption,OSArchitecture,CSName,BuildNumber,Manufacturer -Fragment -PreContent "<h2>Operating System Information</h2>"

#The command below will get the Processor information, convert the result to HTML code as table and store it to a variable
$ProcessInfo = Get-CimInstance -ClassName Win32_Processor | ConvertTo-Html -As List -Property DeviceID,Name,Caption,MaxClockSpeed,SocketDesignation,Manufacturer -Fragment -PreContent "<h2>Processor Information</h2>"

#The command below will get the BIOS information, convert the result to HTML code as table and store it to a variable
$BiosInfo = Get-CimInstance -ClassName Win32_BIOS | ConvertTo-Html -As List -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber -Fragment -PreContent "<h2>BIOS Information</h2>"

#The command below will get the details of Disk, convert the result to HTML code as table and store it to a variable
$Discs = Get-CimInstance -ClassName Win32_LogicalDisk
$LogicalDrives = @()
			Foreach ($LDrive in ($Discs | Where {$_.DriveType -eq 3})){
				$Details = "" | Select "Drive Letter", Label,"Provider Name", "File System", "Disk Size (MB)", "Disk Free Space", "% Free Space"
				$Details."Drive Letter" = $LDrive.DeviceID
				$Details.Label = $LDrive.VolumeName
				$Details."Provider Name" = $LDrive.ProviderName
				$Details."File System" = $LDrive.FileSystem
				$Details."Disk Size (MB)" = [math]::round(($LDrive.size / 1MB))
				$Details."Disk Free Space" = [math]::round(($LDrive.FreeSpace / 1MB))
				$Details."% Free Space" = [Math]::Round(($LDrive.FreeSpace /1MB) / ($LDrive.Size / 1MB) * 100)
				$LogicalDrives += $Details
			}

$DiscInfo = $LogicalDrives | ConvertTo-Html -Fragment -PreContent "<h2>Disc Information</h2>"


#The command below will get the details of Network Configuration, convert the result to HTML code as table and store it to a variable
$Adapters = Get-WmiObject -ClassName Win32_NetworkAdapterConfiguration 
$IPInfo = @()
			Foreach ($Adapter in ($Adapters | Where {$_.IPEnabled -eq $True})) {
				$Details = "" | Select Description, "Physical address", "IP Address / Subnet Mask", "Default Gateway", "DHCP Enabled", DNS, WINS
				$Details.Description = "$($Adapter.Description)"
				$Details."Physical address" = "$($Adapter.MACaddress)"
				If ($Adapter.IPAddress -ne $Null) {
				$Details."IP Address / Subnet Mask" = "$($Adapter.IPAddress)/$($Adapter.IPSubnet)"
					$Details."Default Gateway" = "$($Adapter.DefaultIPGateway)"
				}
				If ($Adapter.DHCPEnabled -eq "True")	{
					$Details."DHCP Enabled" = "Yes"
				}
				Else {
					$Details."DHCP Enabled" = "No"
				}
				If ($Adapter.DNSServerSearchOrder -ne $Null)	{
					$Details.DNS =  "$($Adapter.DNSServerSearchOrder)"
				}
				$Details.WINS = "$($Adapter.WINSPrimaryServer) $($Adapter.WINSSecondaryServer)"
				$IPInfo += $Details
			}
$NetworkAdapterInfo = $IPInfo | ConvertTo-Html -Fragment -PreContent "<h2>Network Information</h2>"

#The command below will get first 10 services information, convert the result to HTML code as table and store it to a variable

#Store the service information to an HTML file
$htmlServiceFileName = "./Services-" + "-" + "$OSName" + ".html"
#$ServicesInfo = Get-CimInstance -ClassName Win32_Service | Select-Object -First 10  |ConvertTo-Html -Property Name,DisplayName,State -Fragment -PreContent "<h2>Services Information</h2>"
$ServicesInfo = Get-CimInstance -ClassName Win32_Service | ConvertTo-Html -Property Name,DisplayName,State -Fragment -PreContent "<h2>Services Information of ($OSName)</h2>" > $htmlServiceFileName
$ServicesInfo = Get-CimInstance -ClassName Win32_Service | Select-Object -First 10  |ConvertTo-Html -Property Name,DisplayName,State -Fragment -PreContent "<h2>Services Information</h2>"
$ServicesInfo = $ServicesInfo -replace '<td>Running</td>','<td class="RunningStatus">Running</td>'
$ServicesInfo = $ServicesInfo -replace '<td>Stopped</td>','<td class="StopStatus">Stopped</td>'

#$LocalAccountInfo =  Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" |
#        Select-Object PSComputerName, Status, Caption, PasswordExpires, AccountType, Description, Disabled, Domain, FullName, InstallDate, LocalAccount, Lockout, Name, PasswordChangeable, PasswordRequired, SID, SIDType | 
#		 ConvertTo-Html   -PreContent "<h2>LOCAL ACCOUNTS INFORMATION</h2>"

$LocalAccountInfo =  Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" |
        Select-Object  Caption, Status, PasswordExpires, AccountType, Description, Disabled, Domain, FullName, InstallDate, LocalAccount, Lockout, Name, PasswordChangeable, PasswordRequired, SID, SIDType | 
		 ConvertTo-Html  -Property Name, Caption, Disabled, Description, Status, PasswordRequired  -PreContent "<h2>LOCAL ACCOUNTS INFORMATION</h2>"

$LocalAccountInfo = $LocalAccountInfo -replace '<td>True</td>','<td class="true">True</td>'
$LocalAccountInfo = $LocalAccountInfo -replace '<td>False</td>','<td class="false">False</td>'

$TableContentHead =  '<h2>WINDOWS COMPLIANCE</h2>'

#Write-Host
#Write-Host Local Password Policy -ForegroundColor DarkGreen
#Write-Host ===================== -ForegroundColor DarkGreen
#    net accounts | Out-Host
#Write-Host



Write-Host "Checking CIS Benchmark" -ForegroundColor Green 
Start-Sleep -s 2
#Check password Policy
Write-Host "`n [+] Begin password policy audit`n" -ForegroundColor DarkGreen
Start-Sleep -s 1
#Check Enforce password history
$ComplianceCount = 0
$TableContent = "$TableContent <table > <tbody><th width='5%'>Sl. No.</th><th width='50%'>Findings</th><th width='30%'>Current Value</th><th width='15%'>Compliance or Not</th></tbody><tbody>"

$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Enforce password history' is set to '24 or more password(s)'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $seceditfile |Select-String "PasswordHistorySize" 
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "24") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Maximum password age 
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "'Maximum password age' is set to '60 or fewer days, but not 0'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $seceditfile |Select-String "MaximumPasswordAge" |select-object -First 1 
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= (($traitement  -gt "0") -and ($traitement  -le "60" )) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Minimum password age
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Minimum password age' is set to '1 or more day"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $seceditfile |Select-String "MinimumPasswordAge"
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "1") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Minimum password length
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Minimum password length' is set to '14 or more character(s)'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $seceditfile |Select-String "MinimumPasswordLength"
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "1") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Password must meet complexity requirements
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $seceditfile |Select-String "PasswordComplexity"
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -match "1") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Store passwords using reversible encryption
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $seceditfile |Select-String "ClearTextPassword"
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -match "0") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"


#check net accounts intel
#Write-Host " [+] Take Service Information" -ForegroundColor DarkGreen
$nomfichierNetAccount = "./AccountsPolicy- " + "$OSName" + ".txt"
net accounts > $nomfichierNetAccount

#Check lock out policy
Write-Host "`n [+] Begin account lockout policy audit`n" -ForegroundColor DarkGreen
Start-Sleep -s 1
#Check Account lockout duration
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Make sure 'Account lockout duration' is set to '15 or more minutes'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $nomfichierNetAccount |Select-String -pattern '(Durée du verrouillage)|(Lockout duration)'
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "15") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Account lockout duration
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Make sure 'Account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $nomfichierNetAccount |Select-String -pattern '(Seuil de verrouillage)|(Lockout threshold)'
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= (($traitement  -gt "0") -and ($traitement  -le "10" )) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Reset account lockout 
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $nomfichierNetAccount |Select-String -pattern "(Fenêtre d'observation du verrouillage)|(Lockout observation window)"
$CurrentValue	= '<td>'+$traitement +'</td>'
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "15") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"


#Check user rights assignment audit
Write-Host "`n [+] Begin user rights assignment audit `n" -ForegroundColor DarkGreen
Start-Sleep -s 1
#Check Account lockout duration
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement		= Get-Content $seceditfile |Select-String "SeTrustedCredManAccessPrivilege"
$CurrentValue	= '<td>'+$traitement +'</td>'
#$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= (-Not($traitement  -match "SeTrustedCredManAccessPrivilege")) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Access this computer from the network
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeNetworkLogonRight" 
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= ($traitement  -notmatch "Everyone") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Act as part of the operating system
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Act as part of the operating system' is set to 'No One'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$traitement = Get-Content $seceditfile |Select-String "SeTcbPrivilege"
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (-Not($traitement  -match "SeTcbPrivilege"))  
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

<#
###Ensure 'Add workstations to domain' is set to 'Administrators'
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "(L1)Ensure 'Add workstations to domain' is set to 'Administrators', Must be Administrators "
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeMachineAccountPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= if ($traitement  -match "Administrator") 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"
#>

#Check Adjust memory quotas for a process
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Make sure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeIncreaseQuotaPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement  -match "LOCAL SERVICE") -and ($traitement  -match "NETWORK SERVICE")) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Allow log on locally
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Allow log on locally' is set to 'Administrators, Users'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeInteractiveLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -notmatch "Guest")  -and ($traitement  -notmatch "Everyone"))
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Allow log on through Remote Desktop Services
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeRemoteInteractiveLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "Remote Desktop Users") -and ($traitement  -notmatch "Guest") ) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Back up files and directories
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Make sure 'Back up files and directories' is set to 'Administrators'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeBackupPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement  -notmatch "Backup Operators")   -and ($traitement  -notmatch "Guest")  -and ($traitement  -notmatch "Everyone"))
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Change the system time
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Make sure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeSystemtimePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE") -and ($traitement  -notmatch "autotimesvc")  -and ($traitement  -notmatch "Everyone")) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Change the time zone
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Make sure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeTimeZonePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE") -and ($traitement  -notmatch "Users") -and ($traitement  -notmatch "Guest")  -and ($traitement  -notmatch "Everyone")) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"

#Check Create a pagefile
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Create a pagefile' is set to 'Administrators'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreatePagefilePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -notmatch "Users") -and ($traitement  -notmatch "Guest")  -and ($traitement  -notmatch "Everyone")) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"


#Check Create a pagefile
$ComplianceCount +=1
$TableContent	= "$TableContent <tr ><td>$ComplianceCount</td>"
$ComplianceName		= "Ensure 'Create a token object' is set to 'No One'"
$TableContent	= "$TableContent <td>$ComplianceName</td>"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreateTokenPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= '<td>'+$traitement +'</td>'
$ComplianceOrNot	= (($traitement  -notmatch "Administrators") -and ($traitement  -notmatch "Users") -and ($traitement  -notmatch "Guest")  -and ($traitement  -notmatch "Everyone")) 
$ComplianceOrNotHTML = ComplianceOrNotToHTML $ComplianceOrNot
ComplianceWriteHost $ComplianceName  $ComplianceOrNot
$TableContent = "$TableContent $CurrentValue $ComplianceOrNotHTML </tr>"















$TableContent = "$TableContent </tbody></table>"
$TableContent = "$TableContentHead $TableContent"

$Report = ConvertTo-HTML -Body "$ToolDetails $ComputerName $OSinfo $ProcessInfo $BiosInfo $DiscInfo $NetworkAdapterInfo $ServicesInfo $LocalAccountInfo $TableContent " -Head $header -Title "SECURITY AUDIT SERVICES, CDAC" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

#The command below will generate the report to an HTML file
$htmlReportFileName = "./CDAC_AUDIT-" + "-" + "$OSName" + ".html"
$Report | Out-File $htmlReportFileName

Set-Location "\"

Write-Host "`n`nAudit Completed`n" -ForegroundColor Yellow
