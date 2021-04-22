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
'  ::::::::::::::::SECURITY:::AUDIT:::SERVICES::::::::::::::::::::::::


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
  if($outpuReverseSid.Length -le 2){
	$outpuReverseSid = "";  
  }

  return $outpuReverseSid

}

function ContentHTML($ComplianceIndex,$ComplianceName,$CurrentValue, $ComplianceOrNot) {
	
$ContentHTML	= "<tr ><td>$ComplianceIndex</td>"
$ContentHTML	= "$ContentHTML <td>$ComplianceName</td>"
$ContentHTML	= "$ContentHTML <td>$CurrentValue</td>"
if ($ComplianceOrNot) {    
$ContentHTML	= "$ContentHTML <td class='true'>Compliance</td>"
Write-Host "       [+] "$ComplianceName -ForegroundColor Green
}
  else {
$ContentHTML	= "$ContentHTML <td class='false'>Non Compliance</td>"
Write-Host "       [-] "$ComplianceName -ForegroundColor Red
  }
$ContentHTML	= "$ContentHTML </tr>"
return $ContentHTML
}
<#
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
#>

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
$gpoFile = "./gpo" + "-" + "$OSName" + ".txt"
gpresult /r /V > $gpoFile | out-null
$gpoFile = "./gpo" + "-" + "$OSName" + ".html"
gpresult /h $gpoFile /f | out-null
#Second command in case of emergency


$auditConfigFile = "./auditpolicy" + "-" + "$OSName" + ".txt"

auditpol.exe /get /Category:* > $auditConfigFile | out-null



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
$htmlServiceFileName = "./SERVICES" + "-" + "$OSName" + ".html"
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
		 ConvertTo-Html  -Property Name, Caption,  Disabled, Description  -PreContent "<h2>LOCAL ACCOUNTS INFORMATION</h2>"

$LocalAccountInfo > "LocalAccounts-$OSName.html"
$LocalAccountInfo = $LocalAccountInfo -replace '<td>True</td>','<td class="true">True</td>'
$LocalAccountInfo = $LocalAccountInfo -replace '<td>False</td>','<td class="false">False</td>'




$ComplianceHTMLHead =  '<h2>WINDOWS COMPLIANCE</h2>'

#Write-Host
#Write-Host Local Password Policy -ForegroundColor DarkGreen
#Write-Host ===================== -ForegroundColor DarkGreen
#    net accounts | Out-Host
#Write-Host



Write-Host "CHECKING CIS BENCHMARKS" -ForegroundColor Green 
Start-Sleep -s 2
#Check password Policy
Write-Host "`n [+] Begin Password Policy Audit`n" -ForegroundColor DarkGreen
Start-Sleep -s 1
#Check Enforce password history
$ComplianceIndex = 0
$ComplianceHTML = "$ComplianceHTML <table > <tbody><th width='5%'>Sl. No.</th><th width='50%'>Findings</th><th width='30%'>Current Value</th><th width='15%'>Compliance or Not</th></tbody><tbody>"

$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Enforce password history' is set to '24 or more password(s)'"
$traitement		= Get-Content $seceditfile |Select-String "PasswordHistorySize" 
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "24") 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Maximum password age 
$ComplianceIndex +=1
$ComplianceName		= "'Maximum password age' is set to '60 or fewer days, but not 0'"
$traitement		= Get-Content $seceditfile |Select-String "MaximumPasswordAge" |select-object -First 1 
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= (($traitement  -gt "0") -and ($traitement  -le "60" )) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Minimum password age
$ComplianceIndex +=1
$ComplianceName		= "Minimum password age' is set to '1 or more day"
$traitement		= Get-Content $seceditfile |Select-String "MinimumPasswordAge"
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "1") 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Minimum password length
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Minimum password length' is set to '14 or more character(s)'"
$traitement		= Get-Content $seceditfile |Select-String "MinimumPasswordLength"
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "1") 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Password must meet complexity requirements
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
$traitement		= Get-Content $seceditfile |Select-String "PasswordComplexity"
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -match "1") 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Store passwords using reversible encryption
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
$traitement		= Get-Content $seceditfile |Select-String "ClearTextPassword"
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -match "0") 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot



#check net accounts intel
#Write-Host " [+] Take Service Information" -ForegroundColor DarkGreen
$nomfichierNetAccount = "./AccountsPolicy- " + "$OSName" + ".txt"
net accounts > $nomfichierNetAccount

#Check lock out policy
Write-Host "`n [+] Begin Account Lockout Policy Audit`n" -ForegroundColor DarkGreen
Start-Sleep -s 1
#Check Account lockout duration
$ComplianceIndex +=1
$ComplianceName		= "Make sure 'Account lockout duration' is set to '15 or more minutes'"
$traitement		= Get-Content $nomfichierNetAccount |Select-String -pattern '(Durée du verrouillage)|(Lockout duration)'
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "15") 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Account lockout duration
$ComplianceIndex +=1
$ComplianceName		= "Make sure 'Account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'"
$traitement		= Get-Content $nomfichierNetAccount |Select-String -pattern '(Seuil de verrouillage)|(Lockout threshold)'
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= (($traitement  -gt "0") -and ($traitement  -le "10" )) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Reset account lockout 
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
$traitement		= Get-Content $nomfichierNetAccount |Select-String -pattern "(Fenêtre d'observation du verrouillage)|(Lockout observation window)"
$CurrentValue	= $traitement 
$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= ($traitement  -ge "15") 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot



#Check user rights assignment audit
Write-Host "`n [+] Begin User Rights Assignment Audit `n" -ForegroundColor DarkGreen
Start-Sleep -s 1
#Check Account lockout duration
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
$traitement		= Get-Content $seceditfile |Select-String "SeTrustedCredManAccessPrivilege"
$CurrentValue	= $traitement 
#$traitement 	= $traitement  -replace "[^0-9]" , ''
$ComplianceOrNot	= (-Not($traitement  -match "SeTrustedCredManAccessPrivilege")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Access this computer from the network
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'"
$chaineSID = Get-Content $seceditfile |Select-String "SeNetworkLogonRight" 
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement  -notmatch "Everyone") 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Act as part of the operating system
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Act as part of the operating system' is set to 'No One'"
$chaineSID = Get-Content $seceditfile |Select-String "SeTcbPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0)
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


<#
###Ensure 'Add workstations to domain' is set to 'Administrators'
$ComplianceIndex +=1

$ComplianceName		= "(L1)Ensure 'Add workstations to domain' is set to 'Administrators', Must be Administrators "

$chaineSID = Get-Content $seceditfile |Select-String "SeMachineAccountPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= if ($traitement  -match "Administrator") 

$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#>

#Check Adjust memory quotas for a process
$ComplianceIndex +=1
$ComplianceName		= "Make sure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
$chaineSID = Get-Content $seceditfile |Select-String "SeIncreaseQuotaPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement  -match "LOCAL SERVICE") -and ($traitement  -match "NETWORK SERVICE"))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Allow log on locally
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Allow log on locally' is set to 'Administrators, Users'"
$chaineSID = Get-Content $seceditfile |Select-String "SeInteractiveLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -notmatch "Guest")  -and ($traitement  -notmatch "Everyone"))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Allow log on through Remote Desktop Services
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
$chaineSID = Get-Content $seceditfile |Select-String "SeRemoteInteractiveLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "Remote Desktop Users") -and ($traitement  -notmatch "Guest") ) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Back up files and directories
$ComplianceIndex +=1
$ComplianceName		= "Make sure 'Back up files and directories' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeBackupPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Change the system time
$ComplianceIndex +=1
$ComplianceName		= "Make sure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
$chaineSID = Get-Content $seceditfile |Select-String "SeSystemtimePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE") -and ($traitement  -notmatch "autotimesvc")  -and ($traitement  -notmatch "Everyone")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Change the time zone
$ComplianceIndex +=1
$ComplianceName		= "Make sure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
$chaineSID = Get-Content $seceditfile |Select-String "SeTimeZonePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE") -and ($traitement  -notmatch "Users") -and ($traitement  -notmatch "Guest")  -and ($traitement  -notmatch "Everyone")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Create a pagefile
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Create a pagefile' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreatePagefilePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Create a token object
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Create a token object' is set to 'No One'"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreateTokenPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0)
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Create global objects
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreateGlobalPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE")  -and ($traitement  -match "SERVICE")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Create permanent shared objects
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Create permanent shared objects' is set to 'No One'"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreatePermanentPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0)
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Create symbolic links
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Create symbolic links'  is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreateSymbolicLinkPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Debug programs
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Debug programs' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeDebugPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Deny access to this computer from the network
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Deny access to this computer from the network' to include 'Guests, Local account'"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyNetworkLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest") -and ($traitement  -match "Local account")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Deny log on as a batch job
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Deny log on as a batch job' to include 'Guests'"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyBatchLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Deny log on as a service
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Deny log on as a service' to include 'Guests'"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyServiceLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Deny log on locally
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Deny log on locally' to include 'Guests'"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyInteractiveLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Deny logon through Remote Desktop Services
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Deny logon through Remote Desktop Services' to include 'Guests, Local account'"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyRemoteInteractiveLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest") -and ($traitement  -match "Local account")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Enable computer and user accounts to be trusted for delegation
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
$chaineSID = Get-Content $seceditfile |Select-String "SeEnableDelegationPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement.Length -eq 0)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Force shutdown from a remote system
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeRemoteShutdownPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Generate security audits
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
$chaineSID = Get-Content $seceditfile |Select-String "SeAuditPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "LOCAL SERVICE")  -and ($traitement  -match "NETWORK SERVICE"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Impersonate a client after authentication
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
$chaineSID = Get-Content $seceditfile |Select-String "SeImpersonatePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE")  -and ($traitement  -match "NETWORK SERVICE")-and ($traitement  -match "NT AUTHORITY\\SERVICE"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Increase scheduling priority
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
$chaineSID = Get-Content $seceditfile |Select-String "SeIncreaseBasePriorityPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "Window Manager\\Window Manager Group"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Load and unload device drivers
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Load and unload device drivers' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeLoadDriverPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Lock pages in memory
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Lock pages in memory' is set to 'No One'"
$chaineSID = Get-Content $seceditfile |Select-String "SeLockMemoryPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Log on as a batch job
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Log on as a batch job' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeBatchLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot



#Check Log on as a service
$ComplianceIndex +=1
$ComplianceName		= "Configure 'Log on as a service'"
$chaineSID = Get-Content $seceditfile |Select-String "SeServiceLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Manage auditing and security log
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Manage auditing and security log' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeSecurityPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Modify an object label
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Modify an object label' is set to 'No One'"
$chaineSID = Get-Content $seceditfile |Select-String "SeRelabelPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Modify firmware environment values
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Modify firmware environment values' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeSystemEnvironmentPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Perform volume maintenance tasks
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeManageVolumePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Profile single process
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Profile single process' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeProfileSingleProcessPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Profile system performance
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"
$chaineSID = Get-Content $seceditfile |Select-String "SeSystemProfilePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "NT SERVICE\\WdiServiceHost"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Replace a process level token
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
$chaineSID = Get-Content $seceditfile |Select-String "SeAssignPrimaryTokenPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "LOCAL SERVICE") -and ($traitement  -match "NETWORK SERVICE"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Restore files and directories
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Restore files and directories' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeRestorePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Shut down the system
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Shut down the system' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeShutdownPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Take ownership of files or other objects
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
$chaineSID = Get-Content $seceditfile |Select-String "SeTakeOwnershipPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check lock out policy
Write-Host "`n [+] Begin Security Options Audit`n" -ForegroundColor DarkGreen
Start-Sleep -s 1

$ListLocalUser = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
foreach ( $user in $ListLocalUser) {
  if ( $user.sid -like "*-500") {
    $adminName = $user.Name
    $adminStatus = $user.Disabled
    if ($adminStatus -eq $true) {
      $adminStatus = "Disabled"
    }
    else {
      $adminStatus = "Enabled"
    }
  }
  elseif ( $user.sid -like "*-501") {
    $guestName = $user.Name
    $guestStatus = $user.Disabled
    if ($guestStatus -eq $true) {
      $guestStatus = "Disabled"
    }
    else {
      $guestStatus = "Enabled"
    }

  }

}
#Check Accounts: Administrator account status
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
$traitement = $adminStatus
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Disabled"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Accounts: Block Microsoft accounts
$ComplianceIndex += 1
$ComplianceName = "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object NoConnectedUser
  $traitement = $traitement.NoConnectedUser
}
else {
  $traitement = "Not configure"
}
$data = @("This policy is disabled","Users can't add Microsoft accounts","XXX","Users can't add or log on with Microsoft accounts")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "3"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Accounts: Guest account status
$ComplianceIndex +=1
$ComplianceName		= "Ensure 'Accounts: Guest account status' is set to 'Disabled'"
$traitement = $guestStatus
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Disabled"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Accounts: Limit local account use of blank passwords to console logon only
$ComplianceIndex += 1
$ComplianceName = "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object LimitBlankPasswordUse
  $traitement = $traitement.LimitBlankPasswordUse
}
else {
  $traitement = "not configure"
}
$data = @("Disabled","Enabled")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Accounts: Rename administrator account
$ComplianceIndex +=1
$ComplianceName		= "Configure 'Accounts: Rename administrator account'"
$traitement = $adminName
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -notmatch "Administrator"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Accounts: Rename guest account
$ComplianceIndex +=1
$ComplianceName		= "Configure 'Accounts: Rename guest account'"
$traitement = $guestName
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -notmatch "Guest"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


$ComplianceHTML = "$ComplianceHTML </tbody></table>"
$ComplianceHTML = "$ComplianceHTMLHead $ComplianceHTML"

$Report = ConvertTo-HTML -Body "$ToolDetails $ComputerName $OSinfo $ProcessInfo $BiosInfo $DiscInfo $NetworkAdapterInfo $ServicesInfo $LocalAccountInfo $ComplianceHTML " -Head $header -Title "SECURITY AUDIT SERVICES, CDAC" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

#The command below will generate the report to an HTML file
$htmlReportFileName = "./CDAC_AUDIT" + "-" + "$OSName" + ".html"
$Report | Out-File $htmlReportFileName

Set-Location "\"

Write-Host "`n`nAudit Completed`n" -ForegroundColor Yellow
