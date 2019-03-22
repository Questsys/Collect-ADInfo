<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.160
	 Created on:   	3/15/2019 3:32 PM
	 Created by:   	b_mag
	 Organization: 	
	 Filename:     	Send-data.ps1
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>

param
(
	[parameter(Mandatory = $true)]
	[string]$Path,
	[parameter(Mandatory = $false)]
	[boolean]$EmailResults = $false,
	[parameter(Mandatory = $false)]
	[string]$emailaddress,
	[parameter(Mandatory = $false)]
	[string]$SMTPServer,
	[parameter(Mandatory = $false)]
	[System.Management.Automation.PSCredential]
	$Credential = [System.Management.Automation.PSCredential]::Empty
)
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
Write-Color -Text "Loading Module ", "Microsoft.Powershell.Archive" -Color Green, Yellow
$result = load-mod -module "microsoft.PowerShell.archive" -name "Archive"
if ($result -eq $false)
{ exit }

#compress all files in outputpath and create export.zip
Write-Color -Text "Compressing files in data directory to export.zip" -Color Green
Compress-Archive -Path ($path + "\data\*") -CompressionLevel Optimal -DestinationPath ($path + "\export.zip") -Force

if ($EmailResults)
{
	if ($Credential -eq [System.Management.Automation.PSCredential]::Empty)
	{
		$Credential = Get-Credential -Message "Enter Email Server Credential"
	}
	$fuser = Read-Host "Enter The Frome User for Email"
	Write-Color -Text "Sending Zip to Email Address ","$($emailaddress)"," Using Server:","$($SMTPServer)" -Color Green,Yellow,Green,Yellow
	#email export.zip to smtp address using SMTP server.
	Send-MailMessage -Attachments ($Path + "\export.zip") -To $emailaddress -Subject "AD Data Gather results" -Body "The attached file is the ad data gather collect on computer $($env:COMPUTERNAME) on $([datetime]::now)." -SmtpServer $SMTPServer -Port 587 -From $Fuser -Credential $Credential -UseSsl
	
}
Write-Color -Text "Finished." -Color Green
