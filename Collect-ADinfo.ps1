<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2018 v5.5.154
	 Created on:   	8/17/2018 10:02 AM
	 Created by:   	Gary Cook
	 Organization: 	Quest
	 Filename:     	Collect-ADinfo.ps1
	===========================================================================
	.DESCRIPTION
		Script collects and write out AD Information.
	.SYNOPSIS
		This script gathers the most important AD information and creates an output word document, as well as saving the data to a collection
		of JSON files for later reference.
	.PARAMETER
		Directory
			The location of the output of this script should be a complete path to a directory on a local hard drive.
		TargetDC
			The starting Domain Controller for the gathering of data. if left black the localhost is assumed to be a DC.
	.EXAMPLE
		collect-adinfo -directory "c:\scripts" -TargetDC Server1
			This runs the collection and saves all the data to the c:\scripts directory using the DC "Server1" as the starting point for collection.
#>
[CmdletBinding()]
param
(
	[parameter(Mandatory = $true)]
	[string]$Directory,
	[parameter(Mandatory = $false)]
	[string]$targetDC
)
Begin
{
	$ScriptName = $MyInvocation.MyCommand.ToString()
	$LogName = "Application"
	$ScriptPath = $MyInvocation.MyCommand.Path
	$Username = $env:USERDOMAIN + "\" + $env:USERNAME
	
	New-EventLog -Source $ScriptName -LogName $LogName -ErrorAction SilentlyContinue
	
	$Message = "Script: " + $ScriptPath + "`nScript User: " + $Username + "`nStarted: " + (Get-Date).toString()
	Write-EventLog -LogName $LogName -Source $ScriptName -EventID "104" -EntryType "Information" -Message $Message
	
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
	
	#Function to send object to file as JSON
	function Output-Json ($object, $filename,$depth)
	{
		if ($depth -eq $null)
		{
			$depth = 1
		}
		Write-Color -Text "Converting Object $($filename) to JSON" -Color Green
		$JSON = $object | ConvertTo-Json -Depth $depth
		Write-Color -Text "Writing Object $($filename) to file" -Color Green
		$JSON | Out-File -FilePath "$($Directory)\$($filename).txt" -Force
		Write-Color -Text "Writing Complete" -Color Green
		
	}
	
	#function to collect information and write to output file
	#commented out due to issues
	<#function collect-data ($command, $filename, $title, $color)
	{
		Write-Color -Text $title -Color $color
		$object = Invoke-Expression -Command $command 
		Output-Json -object $object -filename $filename
	}#>
	
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
	
	Function OutputTimeServerRegistryKeys
	{
		Param ([string]$DCName)
		
		Write-Color -Text "Getting TimeServer Registry Keys for domain controller" -Color Green
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
		
		Write-Color -Text "Getting AD Database, Logfile and SYSVOL locations" -Color Green
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
		$obj | Add-Member -MemberType NoteProperty -Name DSADatabaseFileSize -Value $DSADatabaseFileSize
		
		return $obj
	}
	
	function CountOUObjects ($OU,$Server)
	{
		
		[int]$UserCount = 0
		[int]$ComputerCount = 0
		[int]$GroupCount = 0
		
		$Results = Get-ADUser -Filter * -SearchBase $OU.DistinguishedName -Server $Server -EA 0
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
		
		$Results = Get-ADComputer -Filter * -SearchBase $OU.DistinguishedName -Server $Server -EA 0
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
		
		$Results = Get-ADGroup -Filter * -SearchBase $OU.DistinguishedName -Server $Server -EA 0
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
	
	
	function Get-RIDsremainingAdPsh
	{
		
		param ($domainDN)
		
		$property = get-adobject "cn=rid manager$,cn=system,$domainDN" -property ridavailablepool -server ((Get-ADDomain $domaindn).RidMaster)
		
		$rid = $property.ridavailablepool
		
		[int32]$totalSIDS = $($rid) / ([math]::Pow(2, 32))
		
		[int64]$temp64val = $totalSIDS * ([math]::Pow(2, 32))
		
		[int32]$currentRIDPoolCount = $($rid) – $temp64val
		
		$ridsremaining = $totalSIDS – $currentRIDPoolCount
		$obj = New-Object System.Management.Automation.PSObject
		$obj | add-member -MemberType NoteProperty -Name RIDsIssued -Value $currentRIDPoolCount
		$obj | add-member -MemberType NoteProperty -Name RIDsRemaining -Value $ridsremaining
		
		return $obj
		#Write-Host "RIDs issued: $currentRIDPoolCount"
		
		#Write-Host "RIDs remaining: $ridsremaining"
		
	}
	function count-groupusers ($group,$server)
	{
		$temp = Get-ADGroup -Identity $group -Properties * -Server $server -ErrorAction SilentlyContinue
		$count = 0
		foreach ($member in $temp.members)
		{
			try
			{
				$user = Get-ADUser -Identity $member -Properties * -Server $server -ErrorAction SilentlyContinue
				$count += 1
			}
			catch
			{
			}
		}
		return $count
	}
	
	function get-adtest ($server)
	{
		
		$utest = Get-ADUser -Filter * -Properties * -Server $server | ?{ $_.samaccountname -like 'n*' }
		$OUtest = Get-ADOrganizationalUnit -Filter * -Properties * -Server $server | ?{ $_.name -like 'd*' }
		$gtest = Get-ADGroup -Filter * -Properties * -Server $server | ?{ ($_.members | measure).count -gt 5 }
				
	}
	#	Dotsource in the functions you need.
}
Process
{
	#clear the screen
	cls
	#check the version of powershell if version 5 install Word module
	$ver = $PSVersionTable.psversion
	if ($ver -like '5*')
	{
		Write-Color -Text "Installing the Word Module from PowerShell Gallery" -Color Green
		Install-PackageProvider -Name nuget -MinimumVersion 2.8.5.201 -Force -Confirm:$false -ErrorAction SilentlyContinue
		install-module PSWriteWord -Force -Confirm:$false -SkipPublisherCheck -ErrorAction SilentlyContinue
		
	}
	else
	{
		Write-Color -Text "Powershell Version Incompatable Stopping" -Color Red
		end
		
	}
	#test to see if group policy powershell module is available
	if (!(get-module grouppolicy))
	{
		Write-Color -Text "The Group Policy Module is not loaded" -Color Red
		Write-Color -Text "Checking the module availability" -Color Yellow
		If (!(Get-Module -ListAvailable grouppolicy))
		{
			Write-Color -Text "The groupolicy Module is not available on this system!!" -Color Red
			Write-Color -Text "Unable to proceed!!!" - Red
			exit
		}
		else
		{
			Write-Color -Text "Attempting to load the groupolicy Module" -Color Green
			Import-Module grouppolicy -ErrorAction SilentlyContinue
			if (!(Get-Module grouppolicy))
			{
				Write-Color -Text "Unable to load module!!!" -Color Red
				Write-Color -Text "Unable to proceed!!!" - Red
				exit
			}
			else
			{
				Write-Color -Text "Module Loaded proceeding...." -Color Green
			}
		}
		
	}
	else
	{
		Write-Color -Text "Group Policy Module Loaded proceeding...." -Color Green
	}
	#test to see if ad powershell module is available
	if (!(get-module ActiveDirectory))
	{
		Write-Color -Text "The Active Directory Module is not loaded" -Color Red
		Write-Color -Text "Checking the module availability" -Color Yellow
		If (!(Get-Module -ListAvailable activedirectory))
		{
			Write-Color -Text "The Active Directory Module is not available on this system!!" -Color Red
			Write-Color -Text "Unable to proceed!!!" - Red
			exit
		}
		else
		{
			Write-Color -Text "Attempting to load the Active Directory Module" -Color Green
			Import-Module ActiveDirectory -ErrorAction SilentlyContinue
			if (!(Get-Module activedirectory))
			{
				Write-Color -Text "Unable to load module!!!" -Color Red
				Write-Color -Text "Unable to proceed!!!" - Red
				exit
			}
			else
			{
				Write-Color -Text "Module Loaded proceeding...." -Color Green
			}
		}
		
	}
	else
	{
		Write-Color -Text "Active Directory Module Loaded proceeding...." -Color Green
	}
	#if TargetDC is blank check to see if current computer is a DC
	if ($targetDC -eq "")
	{
		if (!(Get-ADDomainController -Server (get-computerinfo).csname))
		{
			Write-Color -Text "This computer is not a domain controller exiting..." -Color Red
			exit
			
		}
		else
		{
			Write-Color -Text "Using Local Computer becasue it is a domain controller" -Color Green
			$targetDC = (Get-ComputerInfo).csname
			
		}
	}
	else
	{
		#add check to make sure target dc is available for command (future)	
	}
	
	#constants for reference
	#schema version table
	$schversion = @()
	
	$os = @("Windows 2000 Server", "Windows Server 2003", "Windows Server 2003 R2", "Windows Server 2008", "Windows Server 2008 R2", "Windows Server 2012", "Windows Server 2012 R2", "Windows Server 2016")
	$ver = @("13", "30", "31", "44", "47", "56", "69", "87")
	for ($i = 0; $i -le ($os.Length);$i++)
	{
		$sch = New-Object System.Management.Automation.PSObject
		$sch | Add-Member -MemberType NoteProperty -Name OS -Value $null
		$sch | Add-Member -MemberType NoteProperty -Name Version -Value $null
		$sch.os = $os[$i]
		$sch.version = $ver[$i]
		$schversion += $sch
	}
	
	
	#prepare the Word Report Document
	$template = "$PSScriptRoot\ADTemplate.docx"
	$wordfile = "$($Directory)\AD Assesment Deliverable.docx"
	$wordDoc = get-WordDocument -filepath $template
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "AD ASSESSMENT OVERVIEW" -HeadingType Heading1 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was Tasked with performing and Active Directory assessment for your company.  This deliverable was produced with the results of our script-based investigation of your AD Environment.  Quest used a custom script developed in house to capture your current configuration, health, and performance information." -Supress $true
	#$paragraph = Add-WordParagraph -WordDocument $wordDoc -Supress $True # Empty Line
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "ASSESSMENT STRUCTURE" -HeadingType Heading2 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "This deliverable is broken into 3 main sections." -Supress $true
	#$paragraph = Add-WordParagraph -WordDocument $wordDoc -Supress $True # Empty Line
	$ListOfItems = @('Overview of the current configuration of Active Directory', 'Forest', 'Domains', 'Sites', 'Features', 'AD object reports covering Users, Groups, Computers, and GPOs.', 'Performance and health results')
	$OverrideLevels = @(0, 1, 1, 1, 1, 0, 0)
	$paragraph = Add-WordList -WordDocument $wordDoc -ListType Numbered -ListData $ListOfItems -ListLevels $OverrideLevels -Supress $true
	#$paragraph = Add-WordParagraph -WordDocument $wordDoc -Supress $True # Empty Line
	
	
	
	
	
	#Begin Collection of information
	Write-Color -Text "Starting Collection of AD Data" -Color Green
	
	#Process forest info
	#below line commented out do to issues
	#collect-data -command "Get-ADForest -Server $($targetDC)" -filename "ForestSummary" -title "Getting Forest Information" -color Green
	
	
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "ACTIVE DIRECTORY CONFIGURATION" -HeadingType Heading1 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "FOREST" -HeadingType Heading2 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "CONFIGURATION" -HeadingType Heading3 -Supress $true
	
	Write-Color -Text "Getting Forest Information" -Color Green
	$forest = Get-ADForest -Server $targetDC
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the forest $($forest.name) and pull the configuration contained in the table below." -Supress $true
	#send Forest info to file
	Output-Json -object $forest -filename "Forestsummary" -depth 1
	$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $forest -Design MediumShading1Accent5 -Transpose -Supress $true -AutoFit Window
	
	Write-Color -Text "Collectimng Schema Information" -Color Green
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "SCHEMA" -HeadingType Heading3 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Schema for Forest $($forest.name) and pull the Information contained in the table below." -Supress $true
	
	#process schema info
	$schpath = (Get-ADRootDSE -Server $targetDC).schemanamingcontext
	$schema = Get-ADObject $schpath -Properties *
	$schout = $schema | select name, objectversion, modified
	$LObj = $schversion | ?{ $_.version -eq $schout.objectversion }
	$Label = $LObj.os
	$schout | Add-Member -MemberType NoteProperty -Name SchemaVersion -Value $Label -force
	$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $schout -Design MediumShading1Accent5 -Transpose -Supress $true -AutoFit Window
	Output-Json -object $schema -filename "Schema" -depth 1
	
	Write-Color -Text "Collectimng Forest Optional Features" -Color Green
	#process optional Features
	$optfull = Get-ADOptionalFeature -filter * -Properties * -Server $targetDC
	$optout =  $optfull | select Name, Created, featureGUID, featurescope, enabledscopes, modified, protectedfromaccidentaldeletion, required*
	$otpfeatures = $optfull | select name, created, modified
	Output-Json -object $optfull -filename "ADOptionalFeatures" -depth 2
	$optfword = @()
	foreach ($opt in $optfull)
	{
		$obj = New-Object System.Management.Automation.PSObject
		$obj | Add-Member -MemberType NoteProperty -Name Feature -Value $opt.name
		$obj | Add-Member -MemberType NoteProperty -Name Created -Value $opt.created
		$obj | Add-Member -MemberType NoteProperty -Name Modified -Value $opt.Modified
		$optfword += $obj
	}
	
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "OPTIONAL FEATURES" -HeadingType Heading3 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Optional Features for Forest $($forest.name) and pull the Information contained in the table below." -Supress $true
	$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $optfword -Design MediumShading1Accent5 -Supress $true -AutoFit Window
	foreach ($opt in $optout)
	{
		$paragraph = Add-WordParagraph -WordDocument $wordDoc -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Details of the Optional Feature $($opt.name)." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $opt -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
	}
	
	Write-Color -Text "Collectimng Directory Services Info" -Color Green
	$ADForestconfigurationNamingContext = (Get-ADRootDSE -Server $targetDC).configurationNamingContext
	$DirectoryServicesConfigPartition = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$ADForestconfigurationNamingContext" -Partition $ADForestconfigurationNamingContext -Properties *
	Output-Json -object $DirectoryServicesConfigPartition -filename "DirectoryServices"
	$DSWordout = $DirectoryServicesConfigPartition | select name, created, modified, tombstoneLifetime
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "DIRECTORY SERVICES" -HeadingType Heading3 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Directory Services for Forest $($forest.name) and pull the Information contained in the table below." -Supress $true
	$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $DSWordout -Design MediumShading1Accent5 -Transpose -Supress $true -AutoFit Window
	
	Write-Color -Text "Collectimng Forest Trust Info" -Color Green
	#process optional Features
	$trusts = Get-ADTrust -filter * -Properties * -Server $targetDC
	if (($trusts | measure).count -eq 0)
	{
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "TRUSTS" -HeadingType Heading3 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Trusts for Forest $($forest.name) The forest contained no Trusts." -Supress $true
	}
	else
	{
		Output-Json -object $trusts -filename "Trusts"
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "TRUSTS" -HeadingType Heading3 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Trusts for Forest $($forest.name) and pull the Information contained in the table below." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $trusts -Design MediumShading1Accent5 -Transpose -Supress $true -AutoFit Window
	}
		
	Write-Color -Text "Collecting Site Information" -Color Green
	$foresttmp = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $forest.name)
	[array]$ADSites = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($foresttmp).sites
	
	$SoutWord = $ADSites | select name, domains
	
	
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "SITES" -HeadingType Heading3 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Site Information for Forest $($forest.name) and compile the Information in the section below." -Supress $true
	$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $SoutWord -Design MediumShading1Accent5 -Supress $true -AutoFit Window
	
	ForEach ($Site in $ADSites)
	{
		Write-Color -Text "Processing Site $($Site.name)" -Color Green
		Output-Json -object $site -filename "ADSite-$($Site.name)" -depth 1
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "The site $($Site.name) contains the following details." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $site -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
	}
	
	#temp save doc spot to check progress
	#Save-WordDocument -WordDocument $wordDoc -FilePath "$($Directory)\AD Assessment Report.docx"
	
	Write-Color -Text "Collecting Site Link Information" -Color Green
	$sitelink = Get-ADReplicationSiteLink -filter * -Properties * -Server $targetDC
	Output-Json -object $sitelink -filename "Sitelinks"
	$SLoutWord = $sitelink | select name, cost,replinterval,sitesincluded
	
	
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "SITE LINKS" -HeadingType Heading3 -Supress $true
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Site Link Information for Forest $($forest.name) and compile the Information in the section below." -Supress $true
	$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $SloutWord -Design MediumShading1Accent5 -Supress $true -AutoFit Window
	
	ForEach ($link in $sitelink)
	{
		Write-Color -Text "Processing Site Link $($link.name)" -Color Green
		Output-Json -object $link -filename "ADSitelink-$($link.name)" -depth 1
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "The site link $($link.name) contains the following details." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $link -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
	}
	
	Write-Color -Text "Collecting Site Link Bridge Information" -Color Green
	$sitelinkbridge = Get-ADReplicationSiteLinkBridge -filter * -Properties * -Server $targetDC
	if (($sitelinkbridge | measure).count -ne 0)
	{
		Output-Json -object $sitelinkbridge -filename "Sitelinkbridges"
		$SLBoutWord = $sitelinkbridge | select name, sitelinksincluded
		
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "SITE LINK BRIDGES" -HeadingType Heading3 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Site Link Bridge Information for Forest $($forest.name) and compile the Information in the section below." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $SLBoutWord -Design MediumShading1Accent5 -Supress $true -AutoFit Window
		
		ForEach ($bridge in $sitelinkbridge)
		{
			Write-Color -Text "Processing Site Link Bridge $($bridge.name)" -Color Green
			Output-Json -object $bridge -filename "ADSitelinkbridge-$($bridge.name)" -depth 1
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "The site link bridge $($bridge.name) contains the following details." -Supress $true
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $bridge -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
		}
	}
	else
	{
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "SITE LINK BRIDGES" -HeadingType Heading3 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to read the Site Link Bridge Information for Forest $($forest.name).  There are no site link bridges in the forest." -Supress $true
	}
	Write-Color -Text "Forest Information Complete" -Color Green
	
	Write-Color -Text "Starting collection on Domains" -Color Green
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAINS" -HeadingType Heading2 -Supress $true
	$adm = @()
	foreach ($dom in $forest.domains)
	{
		$tempdom = Get-ADDomain -Identity $dom -Server (Get-ADDomainController -Discover -DomainName $dom)
		$rids = Get-RIDsremainingAdPsh -domainDN $tempdom.DistinguishedName
		$obj = New-Object System.Management.Automation.PSObject
		#$obj | Add-Member -MemberType NoteProperty -Name Name -Value $tempdom.name
		$obj | Add-Member -MemberType NoteProperty -Name NetbiosName -Value $tempdom.netbiosname
		$obj | Add-Member -MemberType NoteProperty -Name DNSRoot -Value $tempdom.DNSRoot
		$obj | Add-Member -MemberType NoteProperty -Name DomainMode -Value $tempdom.DomainMode
		$obj | Add-Member -MemberType NoteProperty -Name ForestRoot -Value $(if ($dom -eq $forest.rootdomain) { $true }	else { $false })
		$obj | Add-Member -MemberType NoteProperty -Name RIDsIssued -Value $rids.ridsissued
		$obj | Add-Member -MemberType NoteProperty -Name RIDsRemaining -Value $rids.ridsremaining
		$adm += $obj
	}
	$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest Discovered the following list of domains in the forest $($forest.name) and will detail each in a section section." -Supress $true
	$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $adm -Design MediumShading1Accent5 -AutoFit Window -MaximumColumns 7
	
	#temp save doc spot to check progress
	#Save-WordDocument -WordDocument $wordDoc -FilePath "$($Directory)\AD Assessment Report.docx"
	#pause
	#Process each domain
	
	foreach ($domain in $forest.domains)
	{
		#get domain information
		Write-Color -Text "Processing Domain $($domain)" -Color Green
		Write-Color -Text "Processing Domain Information" -Color Green
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAIN: $($domain)" -HeadingType Heading3 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest was able to pull information from the domain $($domain) and compile it into the following table below." -Supress $true
				
		$temp = Get-ADDomain -Identity $domain -Server $targetDC
		Output-Json -object $temp -filename "Domain-$($domain)"
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $temp -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
		Write-Color -Text "Processing Domain Controllers" -Color Green
		#get target DC in Domain
		$TDC = Get-ADDomainController -Discover -DomainName $domain
		$dcs = Get-ADDomainController -Filter * -server $TDC
		$tempdc = $dcs | select name,domain,enabled,isglobalcatalog,isreadonly,site
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "The following details the domain controllers in the domain $($domain).  Each Domain Controller is broken out into its own section." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $tempdc -Design MediumShading1Accent5 -Supress $true -AutoFit Window -MaximumColumns 6
		
		
		
		
		foreach ($dc in $dcs)
		{
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAIN CONTROLLER: $($dc.name)" -HeadingType Heading4 -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Domain Controller $($dc.name) details." -Supress $true
			
			Write-Color -Text "Processing Domain Controller $($dc.name)" -Color Green
			Output-Json -object $dc -filename "Domain-$($domain)-DC-$($dc.name)"
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $dc -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window 
			Write-Color -Text "Getting AD Database Information" -Color Green
			$addb = OutputADFileLocations $dc.HostName
			Output-Json -object $addb -filename "$($dc.name)-addatabase"
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Domain Controller $($dc.name) database details." -Supress $true
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $addb -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
			Write-Color -Text "Getting Time Sync Information" -Color Green
			$ts = OutputTimeServerRegistryKeys $dc.HostName
			Output-Json -object $ts -filename "$($dc.name)-timesync"
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Domain Controller $($dc.name) time sync details." -Supress $true
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $ts -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
			Write-Color -Text "Getting DNS Server Information" -Color Green
			$dns = Get-DnsServerSetting -All -ComputerName $dc.name -ErrorAction SilentlyContinue
			if (($dns | measure).count -ne 0)
			{
				Output-Json -object $dns -filename "$($dc.name)-DNSSettings"
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "Domain Controller $($dc.name) DNS Server details." -Supress $true
				$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $dns -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
			}
			else
			{
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "Domain Controller $($dc.name) DNS Server details." -Supress $true
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "This Domain Controller is not a DNS Server." -Supress $true
			}
			
		}
		
		
		Write-Color -Text "Getting AD DNS Zones" -Color Green
		$DNSZones = Get-DNSServerZone -ComputerName $targetDC | select *
		Output-Json -object $DNSZones -filename "$($domain)-DNSZones" -depth 2
		$DNSZOut = $DNSZones | select ZoneName,ZoneType,replicationscope,IsDSIntegrated,IsReverseLookupZone,IsAutoCreated
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAIN DNS ZONES" -HeadingType Heading4 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest dicovered the following DNS Zones for the domain $($domain).  Details are included in the table below." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $DNSZout -Design MediumShading1Accent5 -Supress $true -AutoFit Window -MaximumColumns 6
		
		$DNSDSSettings = Get-DnsServerDsSetting
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "DNS DS Settings for the domain $($domain) are included in the table below." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $DNSDSSettings -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
		
		
		Write-Color -Text "Getting AD Domain Password Policy" -Color Green
		$ADPassPol = Get-ADDefaultDomainPasswordPolicy -Server $targetDC
		Output-Json -object $ADPassPol -filename "$($domain)-ADPasswordPolicy"
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAIN PASSWORD POLICY" -HeadingType Heading4 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest dicovered the following default password policy for the domain $($domain)and below is a table of the details." -Supress $true
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $ADPassPol -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
		
		Write-Color -Text "Getting AD Domain Fine Grained Password Policy" -Color Green
		$ADFGPassPol = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -Server $targetDC
		if (($ADFGPassPol | measure).count -ne 0)
		{
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAIN FINE GRAINED PASSWORD POLICY" -HeadingType Heading4 -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest dicovered the following Fine Grained password policy for the domain $($domain) and below is a Summary table With detail tables of each policy to follow." -Supress $true
			$tempfgp = $ADFGPassPol | select Name,Description,Precedence,Appliesto
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $tempfgp -Design MediumShading1Accent5 -Supress $true -AutoFit Window
			foreach ($FGP in $ADFGPassPol)
			{
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAIN FGP Policy $($FGP.name)" -HeadingType Heading5 -Supress $true
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "The deatils of the FGP Policy $($FGP.name) are contained in the table below." -Supress $true
				$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $FGP -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
			}
			Output-Json -object $ADFGPassPol -filename "$($domain)-ADFineGrainedPasswordPolicy"
		}
		else
		{
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAIN FINE GRAINED PASSWORD POLICY" -HeadingType Heading4 -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest dicovered the domain $($domain) contains no fine grained password policies." -Supress $true
		}
		
		#stop point to write word doc to debug
		#Save-WordDocument -WordDocument $wordDoc -FilePath "$($Directory)\AD Assessment Report.docx"
		#pause
		
		Write-Color -Text "Processinmg AD Object Information for Domain $($domain)" -Color Green
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "AD OBJECTS" -HeadingType Heading3 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "This section details out the information on AD object in the domain $($domain).  The objects contained in the section include OUs,Users, Groups, Group Policy Objects, and Printers." -Supress $true
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "GROUP POLICY OBJECTS (GPO)" -HeadingType Heading4 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "This section details out the GPOs in the domain $($domain)." -Supress $true
		Write-Color -Text "Processing Group Policy" -Color Green
		$GPO = get-gpo -domain $domain -all
		$gpoout = $GPO | select displayname, gpostatus,creationtime
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $gpoout -Design MediumShading1Accent5 -Supress $true -AutoFit Window
		Output-Json -object $GPO -filename "$($domain)-GPOs" -depth 2
		foreach ($gp in $GPO)
		{
			Output-Json -object $gp -filename "$($domain)-GPO-$($gp.displayname)" -depth 1
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "GPO - $($gp.displayname)" -HeadingType Heading5 -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Details of the GPO $($gp.displayname)." -Supress $true
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $gp -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
		}
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "ORGANIZATIONAL UNITS (OU)" -HeadingType Heading4 -Supress $true
		
		
		Write-Color -Text "Processing Organizational Units" -Color Green
		$ous = Get-ADOrganizationalUnit -Filter * -Properties * -Server $targetDC
		$oustotal = @()
		foreach ($ou in $ous)
		{
			$counts = CountOUObjects -OU $ou -Server $targetDC
			$ou | Add-Member -MemberType NoteProperty -Name UserCount -Value $counts.UserCount -Force
			$ou | Add-Member -MemberType NoteProperty -Name ComputerCount -Value $counts.ComputerCount -Force
			$ou | Add-Member -MemberType NoteProperty -Name GroupCount -Value $counts.GroupCount -Force
			Output-Json -object $ou -filename "$($domain)-OU-$($ou.name)"
			$oustotal += $ou
		}
		
		Output-Json -object $oustotal -filename "$($domain)-OU" -depth 2
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Summary of OUs in the domain $($domain)." -Supress $true
		$ouout = $oustotal | select Name, Created, Protectedfromaccidentaldeletion, linkedgrouppolicyobjects, usercount, computercount, groupcount
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $ouout -Design MediumShading1Accent5 -Supress $true -AutoFit Window -MaximumColumns 7
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "GROUPS" -HeadingType Heading4 -Supress $true
		$privGroups = @("Account Operators", "Backup Operators", "Print Operators", "Server Operators", "Cert Publishers", "Enterprise Admins", "Domain Admins", "Administrators", "Schema Admins")
		
		Write-Color -Text "Proccessing Groups" -Color Green
		$groups = Get-ADGroup -Filter * -Properties * -Server $targetDC
		$totalGP = ($groups | measure).count
		$BI = 0
		$US = 0
		$UD = 0
		$GS = 0
		$GD = 0
		$LS = 0
		$LD = 0
		
		foreach ($grp in $groups)
		{
			
			if ($grp.isCriticalSystemObject -eq $true)
			{
				$BI += 1
			}
			else
			{
				if ($grp.groupcategory -eq 'Security' -and $grp.groupscope -eq 'Global')
				{
					$GS += 1
				}
				if ($grp.groupcategory -eq 'Distribution' -and $grp.groupscope -eq 'Global')
				{
					$GD += 1
				}
				if ($grp.groupcategory -eq 'Security' -and $grp.groupscope -eq 'DomainLocal')
				{
					$LS += 1
				}
				if ($grp.groupcategory -eq 'Distribution' -and $grp.groupscope -eq 'DomainLocal')
				{
					$LD += 1
				}
				if ($grp.groupcategory -eq 'Security' -and $grp.groupscope -eq 'Universal')
				{
					$US += 1
				}
				if ($grp.groupcategory -eq 'Distribution' -and $grp.groupscope -eq 'Universal')
				{
					$UD += 1
				}
			}
			
		}
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Group Statistics in the domain $($domain)." -Supress $true
		$gout = @{ }
		$gout.Add("Total Groups", $totalgp)
		$gout.Add("Built-In", $BI)
		$gout.Add("Universal Security", $US)
		$gout.Add("Universal Distribution", $UD)
		$gout.Add("Global Security", $GS)
		$gout.Add("Global Distribution", $GD)
		$gout.Add("Domain Local Security", $LS)
		$gout.Add("Domain Local Distribution", $LD)
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $gout -Design MediumShading1Accent5  -Supress $true -AutoFit Window -MaximumColumns 8
		$privgrps = @()
		foreach ($grp in $groups)
		{
			#Write-Color -Text "Processing $($grp.name)" -Color Green
			foreach ($pgrp in $privGroups)
			{
				#Write-Color -Text "testing private group $($pgrp)" -Color Green
				if ($grp.name -eq $pgrp)
				{
					#Write-Color -Text "Found Match..." -Color Green
					$grp | Add-Member -MemberType NoteProperty -Name MemberCount -Value (count-groupusers -group $grp.distinguishedname -server $targetDC) -Force
					$privgrps += $grp
					
				}
			}
		}
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "Privileged Group Statistics in the domain $($domain)." -Supress $true
		$pgout = $privgrps | select Name,MemberCount
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $pgout -Design MediumShading1Accent5 -Supress $true -AutoFit Window
		
		foreach ($pgroup in $privgrps)
		{
			if ($pgroup.MemberCount -ne 0)
			{
				$members = @()
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "$($pgroup.name)" -HeadingType Heading5 -Supress $true
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "The following users are members of this privileged group." -Supress $true
				foreach ($member in $pgroup.members)
				{
					try
					{
						$user = Get-ADUser -Identity $member -Server $targetDC -Properties * -ErrorAction SilentlyContinue
						if (($user | measure).count -ne 0)
						{
							if ($user.passwordlastset -eq $null)
							{
								$LS = $user.created
							}
							else
							{
								$LS = $user.passwordlastset
							}
							$ed = [datetime]::Now
							$PWAge = NEW-TIMESPAN –Start $LS –End $ed
							$obj = New-Object System.Management.Automation.PSObject
							$obj | Add-Member -MemberType NoteProperty -Name LogonID -Value $user.samaccountname
							$obj | Add-Member -MemberType NoteProperty -Name Name -Value $user.DisplayName
							$obj | Add-Member -MemberType NoteProperty -Name PWDAgeinDays -Value $PWAge.days
							$obj | Add-Member -MemberType NoteProperty -Name LastLoggedIn -Value $user.lastlogondate
							$obj | Add-Member -MemberType NoteProperty -Name PWDNoExpire -Value $user.passwordneverexpires
							$obj | Add-Member -MemberType NoteProperty -Name PWDReversable -Value $user.AllowReversiblePasswordEncryption
							$obj | Add-Member -MemberType NoteProperty -Name PWDNotRequired -Value $user.passwordnotrequired
							
							$members += $obj
						}
					}
					catch
					{ }
					
				}
				$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $members -Design MediumShading1Accent5 -Supress $true -AutoFit Window -MaximumColumns 7
			}
		}
		Output-Json -object $groups -filename "$($domain)-Groups" -depth 2
		foreach ($group in $groups)
		{
			Write-Color -Text "Processing Group $($group.name)" -Color Green
			Output-Json -object $group -filename "$($domain)-Group-$($group.samaccountname)"
			
		}
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "USERS" -HeadingType Heading4 -Supress $true
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "User Statistics in the domain $($domain)." -Supress $true
	
		Write-Color -Text "Processing Users" -Color Green
		$users = Get-ADUser -Filter * -Properties * -Server $targetDC
		
		$obj = New-Object System.Management.Automation.PSObject
		$obj | Add-Member -MemberType NoteProperty -Name TotalUsers -Value ($users | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name EnabledUsers -Value (($users | ?{ $_.enabled -eq $true }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name DisabledUsers -Value (($users | ?{ $_.enabled -eq $false }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name LockedUsers -Value (($users | ?{ $_.lockedout -eq $true }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name ExpiredUsers -Value (($users | ?{ $_.accountexpirationdate -ne $null -and $_.accountexpirationdate -lt [datetime]::Now }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name ExpiringUsers -Value (($users | ?{ $_.accountexpirationdate -ne $null -and $_.accountexpirationdate -gt [datetime]::Now }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name PWDNeverExpiresUsers -Value (($users | ?{ $_.passwordneverexpires -eq $true }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name CannotChangePWDUsers -Value (($users | ?{ $_.cannotchangepassword -eq $true }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name PWDExpiredUsers -Value (($users | ?{ $_.passwordexpired -eq $true }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name NoPreAuthUsers -Value (($users | ?{ $_.doesnotrequirepreauth -eq $true }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name ReversableEncryptionUsers -Value (($users | ?{ $_.AllowReversiblePasswordEncryption -eq $true }) | measure).count
		$obj | Add-Member -MemberType NoteProperty -Name StaleUsers -Value (($users | ?{ $_.lastlogondate -lt [datetime]::Now.AddDays(-90) }) | measure).count
		
		$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $obj -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
		Output-Json -object $users -filename "$($domain)-Users" -depth 2
		foreach ($user in $users)
		{
			Write-Color -Text "Processing user $($user.samaccountname)" -Color Green
			Output-Json -object $user -filename "$($domain)-User-$($user.samaccountname)"
			
		}
		
		$paragraph = Add-WordText -WordDocument $wordDoc -Text "HEALTH AND PERFORMANCE" -HeadingType Heading2 -Supress $true
		Write-Color -Text "Processing Health and Performance" -Color Green
		foreach ($domain in $forest.domains)
		{
			Write-Color -Text "Processing Health and Performance for domain $($domain)" -Color Green
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "DOMAIN $($domain)" -HeadingType Heading3 -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "HEALTH CHECK" -HeadingType Heading4 -Supress $true
			
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest performed server tests against the Domain $($domain).  These test included validating Domain Controller Services are running, and that AD replications is successful. A summary report of the findings directly follows the test output." -Supress $true
			#$paragraph = Add-WordParagraph -Supress $true
			#process DCs in the Domain
			Write-Color -Text "Getting DC Info" -Color Green
			$DMTargetDC = Get-ADDomainController -Discover -DomainName $domain
			$dcs = Get-ADDomainController -Filter * -Server $DMTargetDC | select name
			$DCServices = @()
			$DCtime = @()
			foreach ($dc in $dcs)
			{
				$dcalive = Test-Connection -Quiet -Count 1 -ComputerName $dc.name
				if ($dcalive -eq $true)
				{
					Write-Color -Text "Processing DC Service $($dc.name)" -Color Green
					$Services = Get-Service -name ntds, adws, dns, dnscache, kdc, w32time, netlogon, dhcp -ComputerName $dc.name
					$Services | Add-Member -MemberType NoteProperty -Name Server -Value $dc.name -Force
					if (($Services | ?{ $_.Status -ne 'Running' } | measure).count -ne 0)
					{
						$status = "Failed"
						$NRS = ($Services | ?{ $_.Status -ne 'Running' }).name
					}
					else
					{
						$status = "Pass"
						$NRS = "None"
					}
					$Sout = New-Object System.Management.Automation.PSObject
					$Sout | Add-Member -MemberType NoteProperty -Name Server -Value $dc.name
					$Sout | Add-Member -MemberType NoteProperty -Name Status -Value $Status
					$Sout | Add-Member -MemberType NoteProperty -Name FailedServices -Value $NRS
					
					$DCServices += $Sout
					Write-Color -Text "Measuring DC performance $($dc.name)" -Color Green
					$dtime = Measure-Command { get-adtest -server $dc.name }
					$dtime | Add-Member -MemberType NoteProperty -Name Server -Value $dc.name
					$DCtime += $dtime
					
					
				}
				else
				{
					$Sout = New-Object System.Management.Automation.PSObject
					$Sout | Add-Member -MemberType NoteProperty -Name Server -Value $dc.name
					$Sout | Add-Member -MemberType NoteProperty -Name Status -Value "Unavailable"
					$Sout | Add-Member -MemberType NoteProperty -Name FailedServices -Value "N/A"
					
					$DCServices += $Sout
					$dtime = "Failed"
					$dtime | Add-Member -MemberType NoteProperty -Name Server -Value $dc.name
					$DCtime += $dtime
				}
			}
			Write-Color -Text "Adding Services Table" -Color Green
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "A Check was performed against each Domain Controller for the following services: ntds, adws, dns, dnscache, kdc, w32time, netlogon, dhcp. The results of that check are in the table below." -Supress $true
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $DCServices -Design MediumShading1Accent5 -Supress $true -AutoFit Window
			Write-Color -Text "Getting replication info" -Color Green
			$rep1 = Get-ADReplicationPartnerMetadata -Target * -Partition * -Filter * -EnumerationServer $DMTargetDC | Select-Object Server, Partition, Partner, partnertype, lastreplicationattempt, lastreplicationsuccess, lastreplicationresult, ConsecutiveReplicationFailures
			$rout = @()
			foreach ($r in $rep1)
			{
				$server1 = $r.partner
				$server1 = $server1.replace("CN=NTDS Settings,CN=", "")
				$server1 = $server1.substring(0, $server1.indexof(','))
				$r.partner = $server1
				$rout += $r
			}
			
			$rout = $rout | select Server, Partition, Partner, partnertype
			Write-Color -Text "Adding Replication table" -Color Green
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Below is a list of current replication connections in the domain $($domain)." -Supress $true
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $rout -Design MediumShading1Accent5 -Supress $true -AutoFit Window
			$rout2 = @()
			if (($rep1 | ?{ $_.lastreplicationattempt -ne $_.lastreplicationsuccess } | measure).count -ne 0)
			{
				Write-Color -Text "Adding Failed Rep info table" -Color Green
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest detected failed replication connections and will list the details of each below." -Supress $true
				$rout2 = $rep1 | ?{ $_.lastreplicationattempt -ne $_.lastreplicationsuccess }
				foreach ($ro in $rout2)
				{
					Write-Color -Text "Adding Specifi failed Rep info item" -Color Green
					$paragraph = Add-WordText -WordDocument $wordDoc -Text "Details of failed replication connection for server $($ro.server)." -Supress $true
					$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $ro -Design MediumShading1Accent5 -transpose -Supress $true -AutoFit Window
				}
			}
			else
			{
				Write-Color -Text "adding all good rep item" -Color Green
				$paragraph = Add-WordText -WordDocument $wordDoc -Text "All replication connections are currently healthy." -Supress $true
			}
			
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "PERFORMANCE CHECK" -HeadingType Heading4 -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Quest ran a battery of AD commands against the domain $($domain).  Each Test was run against a single DC and the time to execute was measured." -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "Each test does not take into account any lag time of the connect from the testing computer to the destination DC." -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "This should give you an idea of the reposeivness of each DC in the domain, but it is not a solid indicator of actual performce.  Serperate performance data should be gathered." -Supress $true
			$paragraph = Add-WordText -WordDocument $wordDoc -Text "If the Test was executed on a DC against itself the times will be out of scope and inaccurate. The current test machine is $($Env:COMPUTERNAME)" -Supress $true
			
			
			$dout = $DCtime | select Server, totalmilliseconds
			Write-Color -Text "adding performance table data" -Color Green
			$paragraph = Add-WordTable -WordDocument $wordDoc -DataTable $dout -Design MediumShading1Accent5 -Supress $true -AutoFit Window
			
			
			
			
			
		}
		
		
		
		
		
		
	}
	Write-Color -Text "Finished processing domains" -Color Green
	Save-WordDocument -WordDocument $wordDoc -FilePath "$($Directory)\AD Assessment Report.docx"
}
End
	{
		$Message = "Script: " + $ScriptPath + "`nScript User: " + $Username + "`nFinished: " + (Get-Date).toString()
		Write-EventLog -LogName $LogName -Source $ScriptName -EventID "104" -EntryType "Information" -Message $Message
	}
	
	
	
