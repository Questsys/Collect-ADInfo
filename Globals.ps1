#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------

$Global:ADMod = $false
$Global:GPOMod = $false
$Global:Wordmod = $false
$Global:DomainCreds
$Global:DomainController = ""

function count-groupusers ($group)
{
	$count = ($group.members | measure).count
	return $count
}

function Load-Mod ($ModuleName)
{
	if (!(get-module $ModuleName))
	{
		If (!(Get-Module -ListAvailable $ModuleName))
		{
			return $false
		}
		else
		{
			try
			{
				Import-Module $ModuleName -ErrorAction Stop
			}
			catch
			{
				
			}
			
			if (!(Get-Module $ModuleName))
			{
				return $false
			}
			else
			{
				return $true
			}
		}
		
	}
	else
	{
		return $true
	}
}

Function Show-Inputbox
{
	Param ([string]$message = $(Throw "You must enter a prompt message"),
	 [string]$title = "Input",
	 [string]$default
	)
	
	[reflection.assembly]::loadwithpartialname("microsoft.visualbasic") | Out-Null
	[microsoft.visualbasic.interaction]::InputBox($message, $title, $default)
	
}

function write-message ($message)
{
	$label1.text = $label1.text + "`r`n" + $message
}

function get-guitext ($title, $prompt, $buttontype)
{
	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing
	
	$form = New-Object System.Windows.Forms.Form
	$form.Text = $title
	$form.Size = New-Object System.Drawing.Size(300, 200)
	$form.StartPosition = 'CenterScreen'
	
	$OKButton = New-Object System.Windows.Forms.Button
	$OKButton.Location = New-Object System.Drawing.Point(75, 120)
	$OKButton.Size = New-Object System.Drawing.Size(75, 23)
	$OKButton.Text = 'OK'
	$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$form.AcceptButton = $OKButton
	$form.Controls.Add($OKButton)
	
	$CancelButton = New-Object System.Windows.Forms.Button
	$CancelButton.Location = New-Object System.Drawing.Point(150, 120)
	$CancelButton.Size = New-Object System.Drawing.Size(75, 23)
	$CancelButton.Text = 'Cancel'
	$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$form.CancelButton = $CancelButton
	$form.Controls.Add($CancelButton)
	
	$label = New-Object System.Windows.Forms.Label
	$label.Location = New-Object System.Drawing.Point(10, 20)
	$label.Size = New-Object System.Drawing.Size(280, 60)
	$label.Text = $prompt
	$form.Controls.Add($label)
	
	$textBox = New-Object System.Windows.Forms.TextBox
	$textBox.Location = New-Object System.Drawing.Point(10, 90)
	$textBox.Size = New-Object System.Drawing.Size(260, 20)
	$form.Controls.Add($textBox)
	
	$form.Topmost = $true
	
	$form.Add_Shown({ $textBox.Select() })
	$result = $form.ShowDialog()
	
	if ($result -eq [System.Windows.Forms.DialogResult]::OK)
	{
		$x = $textBox.Text
	}
	return $x
}


function Get-DCHealth
{
	[CmdletBinding()]
	# Parameters used in this function
	param
	(
		[Parameter(Position = 0, Mandatory = $true, HelpMessage = "Provide server name", ValueFromPipeline = $true)]
		$Server,
		[Parameter(Position = 1, Mandatory = $true, HelpMessage = "Select DC health check (DCDIAG, Repadmin)", ValueFromPipeline = $true)]
		[ValidateSet("DCDIAG", "Repadmin")]
		[string]$Check
	)
	
	# Checking if server exist
	Try
	{
		$DC = Get-ADDomainController -Identity $Server
	}
	Catch
	{
		Write-Host "Error: " -NoNewline -ForegroundColor Yellow
		Write-Host $_.Exception.Message
		Write-Host
		Break
	}
	
	# Testing connection
	If (!(Test-Connection -Cn $Server -BufferSize 16 -Count 1 -ea 0 -Quiet))
	{
		Write-Warning   "Failed to connect to $Server"
	}
	Else
	{
		If ($Check -eq "DCDIAG")
		{
			$AllDCDiags = @()
			Write-Host "DCDIAG results for"$Server":" -ForegroundColor Yellow -NoNewline
			
			$Dcdiag = (Dcdiag.exe /s:$Server) -split ('[\r\n]')
			$Results = New-Object Object
			$Results | Add-Member -Type NoteProperty -Name "ServerName" -Value $Server
			$Dcdiag | %{
				
				Switch -RegEx ($_)
				{
					"Starting"      { $TestName = ($_ -Replace ".*Starting test: ").Trim() }
					"passed test|failed test"
					{
						If ($_ -Match "passed test")
						{
							$TestStatus = "Passed"
						}
						Else
						{
							$TestStatus = "Failed"
						}
					}
				}
				
				If ($TestName -ne $Null -And $TestStatus -ne $Null)
				{
					$Results | Add-Member -Name $("$TestName".Trim()) -Value $TestStatus -Type NoteProperty -force
					$TestName = $Null; $TestStatus = $Null
				}
			}
			$AllDCDiags += $Results
			$AllDCDiags | fl | Out-String
		}
		ElseIf ($Check -eq "Repadmin")
		{
			$repadmin = @()
			
			Write-Host "REPADMIN results for"$Server":" -ForegroundColor Yellow -NoNewline
			Write-Host " "
			$rep = (Invoke-Command $Server -ScriptBlock { repadmin /showrepl /repsto /csv | ConvertFrom-Csv })
			
			$rep | ForEach-Object {
				
				# Define current loop to variable
				$r = $_
				
				# Adding properties to object
				$REPObject = New-Object PSCustomObject
				$REPObject | Add-Member -Type NoteProperty -Name "Destination DCA" -Value $r.'destination dsa'
				$REPObject | Add-Member -Type NoteProperty -Name "Source DSA" -Value $r.'source dsa'
				$REPObject | Add-Member -Type NoteProperty -Name "Source DSA Site" -Value $r."Source DSA Site"
				$REPObject | Add-Member -Type NoteProperty -Name "Last Success Time" -Value $r.'last success time'
				$REPObject | Add-Member -Type NoteProperty -Name "Last Failure Status" -Value $r.'Last Failure Status'
				$REPObject | Add-Member -Type NoteProperty -Name "Last Failure Time" -Value $r.'last failure time'
				$REPObject | Add-Member -Type NoteProperty -Name "Number of failures" -Value $r.'number of failures'
				
				# Adding object to array
				$repadmin += $REPObject
				
			}
			$repadmin | ft | Out-String
		}
	}
}

#Sample function that provides the location of the script
function Get-ScriptDirectory
{
<#
	.SYNOPSIS
		Get-ScriptDirectory returns the proper location of the script.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory


