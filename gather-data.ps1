<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.159
	 Created on:   	2/26/2019 11:59 AM
	 Created by:   	Gary Cook
	 Organization: 	Quest
	 Filename:     	gather-data.ps1
	===========================================================================
	.DESCRIPTION
		This script is run on a PC in the Target Domain to gather data.
		The Computer should be a domain controller or a Domain Joined PC.
		The Computer requires the following Powershell version 4.0 or 
		higher running on windows server 2012 or windows 8 or higher.
		The Computer Requires the activedirectory powershell module and the grouppolicy module.
		
	.PARAMETER

		Credential - The ActiveDirectory Credential of a user that has full read permission to 
		AD and all data.

		OutputPath - The directory on a local hard disk to store the output data.  A Data subdirectory
		will be created to contain the output files.

	.EXAMPLE
		Gather-Data -Credential (get-credential) -OutputPath "C:\scripts"
#>

param
(
	[parameter(Mandatory = $true)]
	[System.Management.Automation.PSCredential]$Credential,
	[parameter(Mandatory = $true)]
	[string]$OutputPath
)


Function Get-RegistryValue
{
	# Gets the specified registry value or $Null if it is missing
	[CmdletBinding()]
	Param ([string]$path,
		[string]$name,
		[string]$ComputerName)
	If ($ComputerName -eq $env:computername -or $ComputerName -eq "LocalHost")
	{
		$key = Get-Item -LiteralPath $path -EA 0
		If ($key)
		{
			Return $key.GetValue($name, $Null)
		}
		Else
		{
			Return $Null
		}
	}
	Else
	{
		#path needed here is different for remote registry access
		$path1 = $path.SubString(6)
		$path2 = $path1.Replace('\', '\\')
		$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
		$RegKey = $Reg.OpenSubKey($path2)
		$Results = $RegKey.GetValue($name)
		If ($Null -ne $Results)
		{
			Return $Results
		}
		Else
		{
			Return $Null
		}
	}
}

function CountOUObjects ($OU, $Server, $Credential)
{
	
	[int]$UserCount = 0
	[int]$ComputerCount = 0
	[int]$GroupCount = 0
	
	$Results = Get-ADUser -Filter * -SearchBase $OU.DistinguishedName -Server $Server -EA 0 -Credential $Credential
	If ($Null -eq $Results)
	{
		$UserCount = 0
	}
	ElseIf ($Results -is [array])
	{
		$UserCount = $Results.Count
	}
	Else
	{
		$UserCount = 1
	}
	
	$Results = Get-ADComputer -Filter * -SearchBase $OU.DistinguishedName -Server $Server -EA 0 -Credential $Credential
	If ($Null -eq $Results)
	{
		$ComputerCount = 0
	}
	ElseIf ($Results -is [array])
	{
		$ComputerCount = $Results.Count
	}
	Else
	{
		$ComputerCount = 1
	}
	
	$Results = Get-ADGroup -Filter * -SearchBase $OU.DistinguishedName -Server $Server -EA 0 -Credential $Credential
	If ($Null -eq $Results)
	{
		$GroupCount = 0
	}
	ElseIf ($Results -is [array])
	{
		$GroupCount = $Results.Count
	}
	Else
	{
		$GroupCount = 1
	}
	#createou count object
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name UserCount -Value $UserCount
	$obj | Add-Member -MemberType NoteProperty -Name ComputerCount -Value $ComputerCount
	$obj | Add-Member -MemberType NoteProperty -Name GroupCount -Value $GroupCount
	
	return $obj
}

Function OutputTimeServerRegistryKeys
{
	Param ([string]$DCName)
	
	#Write-Color -Text "Getting TimeServer Registry Keys for domain controller" -Color Green
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Config	AnnounceFlags
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Config	MaxNegPhaseCorrection
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Config	MaxPosPhaseCorrection
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters	NtpServer
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters	Type 	
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient	SpecialPollInterval
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider Enabled
	
	$AnnounceFlags = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" "AnnounceFlags" $DCName
	$MaxNegPhaseCorrection = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" "MaxNegPhaseCorrection" $DCName
	$MaxPosPhaseCorrection = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" "MaxPosPhaseCorrection" $DCName
	$NtpServer = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" "NtpServer" $DCName
	$NtpType = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" "Type" $DCName
	$SpecialPollInterval = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" "SpecialPollInterval" $DCName
	$VMICTimeProviderEnabled = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider" "Enabled" $DCName
	$NTPSource = w32tm /query /computer:$DCName /source
	
	If ($VMICTimeProviderEnabled -eq 0)
	{
		$VMICEnabled = "Disabled"
	}
	Else
	{
		$VMICEnabled = "Enabled"
	}
	
	#create time server info array
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name DCName -Value $DCName
	$obj | Add-Member -MemberType NoteProperty -Name TimeSource -Value $NTPSource
	$obj | Add-Member -MemberType NoteProperty -Name AnnounceFlags -Value $AnnounceFlags
	$obj | Add-Member -MemberType NoteProperty -Name MaxNegPhaseCorrection -Value $MaxNegPhaseCorrection
	$obj | Add-Member -MemberType NoteProperty -Name MaxPosPhaseCorrection -Value $MaxPosPhaseCorrection
	$obj | Add-Member -MemberType NoteProperty -Name NtpServer -Value $NtpServer
	$obj | Add-Member -MemberType NoteProperty -Name NtpType -Value $NtpType
	$obj | Add-Member -MemberType NoteProperty -Name SpecialPollInterval -Value $SpecialPollInterval
	$obj | Add-Member -MemberType NoteProperty -Name VMICTimeProvider -Value $VMICEnabled
	
	#[void]$Script:TimeServerInfo.Add($obj)
	return $obj
	
}

Function OutputADFileLocations
{
	Param ([string]$DCName)
	
	#Write-Color -Text "Getting AD Database, Logfile and SYSVOL locations" -Color Green
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters	'DSA Database file'
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters	'Database log files path'
	#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	SysVol
	
	$DSADatabaseFile = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "DSA Database file" $DCName
	$DatabaseLogFilesPath = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "Database log files path" $DCName
	$SysVol = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SysVol" $DCName
	
	#calculation is taken from http://blogs.metcorpconsulting.com/tech/?p=177
	$DITRemotePath = $DSADatabaseFile.Replace(":", "$")
	$DITFile = "\\$DCName\$DITRemotePath"
	$DITsize = ([System.IO.FileInfo]$DITFile).Length
	$DITsize = ($DITsize/1GB)
	$DSADatabaseFileSize = "{0:N3}" -f $DITsize
	
	#create AD Database info array
	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name DSADatabaseFile -Value $DSADatabaseFile
	$obj | Add-Member -MemberType NoteProperty -Name DatabaseLogFilesPath -Value $DatabaseLogFilesPath
	$obj | Add-Member -MemberType NoteProperty -Name SysVol -Value $SysVol
	$obj | Add-Member -MemberType NoteProperty -Name DSADatabaseFileSizeinGB -Value $DSADatabaseFileSize
	
	return $obj
}

function get-localDC ()
{
	
	return $env:LOGONSERVER -replace "\\", ""
}

function save-object ($obj, $filename)
{
	try
	{
		$fn = $OutputPath + "\" + $filename
		$obj | Export-Clixml -Path $fn
		return $true
	}
	catch
	{
		return $_.ErrorDetails.Message
	}
}

#Function to Display multiple colors in One output line for Write-Host
function Write-Color([String[]]$Text, [ConsoleColor[]]$Color = "White", [int]$StartTab = 0, [int]$LinesBefore = 0, [int]$LinesAfter = 0)
{
	$DefaultColor = $Color[0]
	if ($LinesBefore -ne 0) { for ($i = 0; $i -lt $LinesBefore; $i++) { Write-Host "`n" -NoNewline } } # Add empty line before
	if ($StartTab -ne 0) { for ($i = 0; $i -lt $StartTab; $i++) { Write-Host "`t" -NoNewLine } } # Add TABS before text
	if ($Color.Count -ge $Text.Count)
	{
		for ($i = 0; $i -lt $Text.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine }
	}
	else
	{
		for ($i = 0; $i -lt $Color.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine }
		for ($i = $Color.Length; $i -lt $Text.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $DefaultColor -NoNewLine }
	}
	Write-Host
	if ($LinesAfter -ne 0) { for ($i = 0; $i -lt $LinesAfter; $i++) { Write-Host "`n" } } # Add empty line after
}

#function to load modules
function load-mod ($module, $name)
{
	if (!(get-module $module))
	{
		Write-Color -Text "The $($name) Module is not loaded" -Color Red
		Write-Color -Text "Checking the module availability" -Color Yellow
		If (!(Get-Module -ListAvailable $module))
		{
			Write-Color -Text "The $($name) Module is not available on this system!!" -Color Red
			Write-Color -Text "Unable to proceed!!!" - Red
			return $false
		}
		else
		{
			Write-Color -Text "Attempting to load the $($name) Module" -Color Green
			Import-Module $module -ErrorAction SilentlyContinue
			if (!(Get-Module $module))
			{
				Write-Color -Text "Unable to load module!!!" -Color Red
				Write-Color -Text "Unable to proceed!!!" - Red
				return $false
			}
			else
			{
				Write-Color -Text "Module Loaded proceeding...." -Color Green
				return $true
			}
		}
		
	}
	else
	{
		Write-Color -Text "$($name) Module Loaded proceeding...." -Color Green
		return $true
	}
}

#clear the screen
cls
Write-Color -Text "Preparing Data for Discovery" -Color Green

#constants for reference
#schema version table will need to be updated as new versions of server are released that modify the schema
# check https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/cf266003-19e1-4144-a919-bf7adf21254f for latest data

#if the schema.csv file exists load table from file if not populate from data included in code
if (Test-Path -Path ".\schema.csv")
{
	$schvertable = Import-Csv -Path ".\schema.csv" -Header 'OS','Version'
}
else
{
	$schvertable = @()
	
	$os = @("Windows 2000 Server", "Windows Server 2003", "Windows Server 2003 R2", "Windows Server 2008", "Windows Server 2008 R2", "Windows Server 2012", "Windows Server 2012 R2", "Windows Server 2016/Server v1709", "Windows Server 2019/Server V1803/Server V1809")
	$ver = @("13", "30", "31", "44", "47", "56", "69", "87", "88")
	for ($i = 0; $i -le ($os.Length); $i++)
	{
		$sch = New-Object System.Management.Automation.PSObject
		$sch | Add-Member -MemberType NoteProperty -Name OS -Value $null
		$sch | Add-Member -MemberType NoteProperty -Name Version -Value $null
		$sch.os = $os[$i]
		$sch.version = $ver[$i]
		$schvertable += $sch
	}
}

#test if powershell is correct version and operating system is correct version
#test powershell

#check the version of powershell if version 4 or higher
$ver = $PSVersionTable.psversion
if ($ver.major -ge 4)
{
	Write-Color -Text "Current Powershell version greater than 4 actual version is ", "$($ver)" -Color Green, yellow
	Write-Color -Text "Current Dot Net framework version is ", "$([System.Runtime.InteropServices.RuntimeInformation]::get_FrameworkDescription())" -Color Green, Yellow
	Write-Color -Text "Execution can proceed" -Color Green
}
else
{
	Write-Color -Text "Current Powershell version less than 4 actual version is ", "$($ver)" -Color Green, Red
	Write-Color -Text "Current Dot Net framework version is ", "$([System.Runtime.InteropServices.RuntimeInformation]::get_FrameworkDescription())" -Color Green, Yellow
	Write-Color -Text "Powershell Version Incompatable Stopping" -Color Red
	exit
}


#load modules required
Write-Color -Text "Loading Modules" -Color Green
Write-Color -Text "Loading Module ", "ActiveDirectory" -Color Green, Yellow
$result = load-mod -module "activedirectory" -name "Active Directory"
if ($result -eq $false)
{ exit }
Write-Color -Text "Loading Module ", "GroupPolicy" -Color Green, Yellow
$result= load-mod -module "GroupPolicy" -name "GroupPolicy"
if ($result -eq $false)
{ exit }

#create data directory
Write-Color -Text "Creating the Data Directory in $($OutputPath)" -Color Green
New-Item -Path $OutputPath -Name "Data" -ItemType "Directory"
$oldpath = $OutputPath
$OutputPath = $OutputPath + "\data"

#load dc
Write-Color -Text "Getting the Local Domain Controller for this Computer" -Color Green
$dc = get-localDC
write-color -Text "The domain Controller found was ", "$($dc)" -Color Green, Yellow



#main script section
Write-Color -Text "Starting Collection of AD Data" -Color Green

#gather forest base Data
Write-Color -Text "Beginning Forest Data Collection" -Color Green
$forest = Get-ADForest -Server $dc -Credential $Credential
#gather forest Tombstone Lifetime
$tombLT = (Get-ADObject -Server $dc -Credential $Credential -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -Properties tombstoneLifetime).tombstoneLifetime
if ($tombLT -eq $null)
{
	#if no value is returned alternate process
	$tombLT = ([adsi]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$(([adsi]("LDAP://RootDSE")).configurationNamingContext)").tombstoneLifetime
}
if ($tombLT -eq $null)
{
	#unable to get value via powershell or ADSI report error
	$tombLT = "Unable to read value"
}

#if Cross forest is empty replace with None
if ($forest.crossforestreferences -eq $null)
{
	$forest.crossforestreferences = "None"
}
if ($forest.spnsuffixes -eq $null)
{
	$forest.spnsuffixes = "None"
}

if ($forest.upnsuffixes -eq $null)
{
	$forest.upnsuffixes = "None"
}

$forest | Add-Member -MemberType NoteProperty -Name TombstoneLifetime -Value $tombLT -Force
$rslt = save-object -obj $forest -filename "forest.xml"

<#
Put code here to process error creating xml file
#>

Write-Color -Text "Forest Data Collection Complete" -Color Green
#gather Schema Data
Write-Color -Text "Beginning Schema Data Collection" -Color Green
$schema = Get-ADObject (Get-ADRootDSE).schemaNamingContext -Property * -Server $dc -Credential $Credential
$LObj = $schvertable | ?{ $_.version -eq $schema.objectversion }
$Label = $LObj.os
$schema | Add-Member -MemberType NoteProperty -Name SchemaVersion -Value $Label -force
$rslt = save-object -obj $schema -filename "schema.xml"
Write-Color -Text "Schema Data Collection Complete" -Color Green

#gather optional features
Write-Color -Text "Beginning Other Forest Data Collection" -Color Green
$optfull = Get-ADOptionalFeature -filter * -Properties * -Server $dc -Credential $Credential
$rslt = save-object -obj $optfull -filename "Optionalfeatures.xml"


#gather Trust information
$ForestTrusts = Get-ADTrust -filter * -Properties * -Server $dc -Credential $Credential
$rslt = save-object -obj $ForestTrusts -filename "Trusts.xml"

Write-Color -Text "Other Forest Data Collection Complete" -Color Green

#gather forest Site Information old code requires system and user to be domain joined and domain user
Write-Color -Text "Beginning Site Data Collection" -Color Green
$a = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $forest.name)
[array]$ADSites = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($a).sites
# new code to be fixed an implimented
#$adsites = Get-ADReplicationSite -Filter * -Properties * -server $dc -Credential $Credential
$rslt = save-object -obj $ADSites -filename "Sites.xml"

#gather AD Connection information
#sitelink
$sitelink = Get-ADReplicationSiteLink -Filter *
$rslt = save-object -obj $sitelink -filename "sitelink.xml"
#sitelink bridge
$sitelinkbridge = Get-ADReplicationSiteLinkBridge -Filter *
$rslt = save-object -obj $sitelinkbridge -filename "sitelinkbridge.xml"
#all replication connections in forest
$replcon = Get-ADReplicationPartnerMetadata -target $forest.name -Scope forest
$rslt = save-object -obj $replcon -filename "forestReplication.xml"
# all replication connects in forest
$replc = Get-ADReplicationConnection -Filter * -Properties * -Server $dc -Credential $Credential
$rslt = save-object -obj $replc -filename "additionalreplication.xml"

Write-Color -Text "Site Data Collection Complete" -Color Green

$domains = @()
$GPOS = @()
$DomainControllers = @()
$ddns = @()
$OUS = @()
$groups = @()
$users = @()
#get all domain information
Write-Color -Text "Beginning Domain Data Collection" -Color Green
foreach ($dom in $forest.domains)
{
	Write-Color -Text "Processing domain ", "$($dom)" -Color Green, Yellow
	$DDC = Get-ADDomainController -DomainName $dom -Discover
	$DDC = "$($DDC.hostname)"
	
	#base domain info
	$domain = Get-ADDomain -Identity $dom -Server $DDC -Credential $Credential
	$domains += $domain
	#domain GPO Info
	Write-Color -Text "Beginning GPO Data Collection" -Color Green
	$dgpo = Get-GPO -Domain $dom -Server $DDC -All
	Get-GPOReport -all -server $DDC -domain $dom -ReportType XML -Path ($OutputPath + "\$($domain.dnsroot)-GPOReport.xml")
	
	$GPOS += $dgpo
	Write-Color -Text "GPO Data Collection complete" -Color Green
	
	#process Domain Controllers in domain
	$domdc = Get-ADDomainController -Filter * -Credential $Credential -Server $DDC
	$odomdc = @()
	Write-Color -Text "Beginning Domain Controller Data Collection" -Color Green
	foreach ($d in $domdc)
	{
		
		Write-Color -Text "Processing Domain Controller ","$($d.hostname)" -Color Green,yellow
		#get time sync details
		$td = OutputTimeServerRegistryKeys -DCName $d.hostname
		
		$d | Add-Member -MemberType NoteProperty -Name TimeSource -Value $td.NTPSource -Force
		$d | Add-Member -MemberType NoteProperty -Name AnnounceFlags -Value $td.AnnounceFlags -Force
		$d | Add-Member -MemberType NoteProperty -Name MaxNegPhaseCorrection -Value $td.MaxNegPhaseCorrection -Force
		$d | Add-Member -MemberType NoteProperty -Name MaxPosPhaseCorrection -Value $td.MaxPosPhaseCorrection -Force
		$d | Add-Member -MemberType NoteProperty -Name NtpServer -Value $td.NtpServer -Force
		$d | Add-Member -MemberType NoteProperty -Name NtpType -Value $td.NtpType -Force
		$d | Add-Member -MemberType NoteProperty -Name SpecialPollInterval -Value $td.SpecialPollInterval -Force
		$d | Add-Member -MemberType NoteProperty -Name VMICTimeProvider -Value $td.VMICEnabled -Force
		
		#get database details
		$addb = OutputADFileLocations $d.HostName
		$d | Add-Member -MemberType NoteProperty -Name Databaselogfilespath -Value $addb.databaselogfilespath -Force
		$d | Add-Member -MemberType NoteProperty -Name dsadatabasefile -Value $addb.dsadatabasefile -Force
		$d | Add-Member -MemberType NoteProperty -Name sysvol -Value $addb.sysvol -Force
		$d | Add-Member -MemberType NoteProperty -Name dsadatabasefilesizeingb -Value $addb.dsadatabasefilesizeingb -Force
		$odomdc += $d
		
		#get dns details for each DC
		try { $dcdns = Get-DnsServerSetting -all -ComputerName $d.hostname -ea stop }
		catch { }
		if ($dcdns -ne $null)
		{
			$DDNS += $dcdns
		}
		
	}
	
	Write-Color -Text "Domain Controller Data Collection Complete" -Color Green
	
	#DNS Zone Information
	Write-Color -Text "Beginning DNS Zone Data Collection" -Color Green
	$DNSZone = Get-DnsServerZone -ComputerName $DDC | select *
	$DNSZone | Add-Member -MemberType NoteProperty -Name Domain -Value $domain.dnsroot -force
	$rslt = save-object -obj $DNSZone -filename "DNSZone.xml"
	Write-Color -Text "DNS Zone Data Collection Complete" -Color Green
	
	#ad password policy
	Write-Color -Text "Beginning Password Policy Data Collection" -Color Green
	$ADPassPol = Get-ADDefaultDomainPasswordPolicy -Server $DDC
	$ADPassPol | Add-Member -MemberType NoteProperty -Name Domain -Value $domain.dnsroot -Force
	$rslt = save-object -obj $ADPassPol -filename "DomainPasswordPolicy.xml"
	Write-Color -Text "Password Policy Data Collection Complete" -Color Green
	
	#AD Fine Grained Password Policies
	Write-Color -Text "Beginning Fine Grained Password Policy Data Collection" -Color Green
	$ADFGPassPol = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -Server $DDC
	$ADFGPassPol | Add-Member -MemberType NoteProperty -Name Domain -Value $domain.dnsroot -Force
	$rslt = save-object -obj $ADFGPassPol -filename "FineGrainedPasswordPolicy.xml"
	Write-Color -Text "Fine Grained Password Policy Data Collection Complete" -Color Green
	
	
	
	Write-Color -Text "Beginning Organizational Unit Data Collection" -Color Green
	#get all OU in domain
	$dou = Get-ADOrganizationalUnit -Filter * -Properties * -Server $DDC -Credential $Credential
	$dou | Add-Member -MemberType NoteProperty -Name Domain -Value $domain.dnsroot -Force
	
	$c = 0
	
	foreach ($o in $dou)
	{
		#Write-Color -Text "Processing OU ", "$($o.name)" -Color Green, yellow
		Write-Progress -Activity "Processing OU's" -PercentComplete ($c/($dou | measure).count * 100) -Status "OU: $($o.name)"
		
		$oucount = CountOUObjects -OU $o -Server $DDC -Credential $Credential
		$o | Add-Member -MemberType NoteProperty -Name UserCount -Value $oucount.usercount -Force
		$o | Add-Member -MemberType NoteProperty -Name ComputerCount -Value $oucount.computercount -Force
		$o | Add-Member -MemberType NoteProperty -Name groupCount -Value $oucount.groupcount -Force
		$c += 1
		$OUS += $o
	}
	
	Write-Progress -Activity "Processing OU's" -Status "Done" -Completed
	Write-Color -Text "Organizational Unit Data Collection Complete" -Color Green
	
	#group processing
	Write-Color -Text "Beginning Group Data Collection" -Color Green
	$dgroups = Get-ADGroup -Filter * -Properties * -Server $DDC -Credential $Credential
		
	#add domain name to groups
	$dgroups | Add-Member -MemberType NoteProperty -Name Domain -Value $domain.dnsroot -Force
	$dgroups | Add-Member -MemberType NoteProperty -Name MemberCount -Value $null -Force
	$count = 0
	foreach ($g in $dgroups)
	{
		$dgroups[$count].MemberCount = ($g.members | measure).count
		$count += 1
		
	}
	$groups += $dgroups
	Write-Color -Text "Group Data Collection Complete" -Color Green
	
	Write-Color -Text "Beginning User Data Collection" -Color Green
	$dusers = Get-ADUser -Filter * -Properties * -Server $DDC -Credential $Credential
	$time = 0
	$count = 0
	$dusers | Add-Member -MemberType NoteProperty -Name LastLogonCorrected -Value $null -force
	$c = 0
	
	foreach ($u in $dusers)
	{
		#Write-Color -Text "Processing User ", "$($u.samaccountname)", " for LastLogon Data" -Color Green, Yellow, Green
		
		foreach ($d in $domdc)
		{
			Write-Progress -Activity "Processing User's" -Status "Getting $($u.samaccountname) Last Logon Data" -PercentComplete ($c/($dusers | measure).count * 100) -Currentoperation "Reading DC: $($d.hostname)"
			
			$tuser = Get-ADUser $u.samaccountname | get-adobject -server $d.hostname -properties lastlogon
			if ($tuser.lastlogon -gt $time)
			{
				$time = $tuser.lastlogon
			}
		}
		$dt = [datetime]::fromfiletime($time)
		$dusers[$count].lastlogoncorrected = $dt
		$count += 1
		$c += 1
		
	}
	
	$dusers | Add-Member -MemberType NoteProperty -Name Domain -Value $domain.dnsroot -Force
	$users += $dusers
	Write-Progress -Activity "Processing User's" -Status "Done" -Completed
	Write-Color -Text "User Data Collection Complete" -Color Green
	$DomainControllers += $odomdc
	Write-Color -Text "Domain Data Collection Complete" -Color Green
	
}
$rslt = save-object -obj $domains -filename "domains.xml"
$rslt = save-object -obj $GPOS -filename "gpos.xml"
$rslt = save-object -obj $DomainControllers -filename "DomainControllers.xml"
$rslt = save-object -obj $ddns -filename "DNS.xml"
$rslt = save-object -obj $OUS -filename "OUS.xml"
$rslt = save-object -obj $groups -filename "Groups.xml"
$rslt = save-object -obj $users -filename "Users.xml"

Write-Color -Text "All results saved to ", "$($oldpath)", " in the Data Subdirectory" -Color Green, Yellow, Green







