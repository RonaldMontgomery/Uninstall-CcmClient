#Requires -RunAsAdministrator

FUNCTION Update-Registry($path) {
    If(Test-Path $path) {write-verbose "$(Get-Date -Format g): Deleting $($path)"; Remove-Item -Path $path -Force -Recurse -Confirm:$false -Verbose}
    }


#https://www.optimizationcore.com/deployment/sccm-client-complete-remove-uninstall-powershell-script/
FUNCTION Uninstall-CcmClient{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$RemoveAll
                   )
        Write-Verbose "$(Get-Date -Format g): Beginning Uninstall-CCMClient function."
        Try {
            If(Test-Path "$($env:windir)\ccmsetup\ccmsetup.exe" -PathType Leaf){
                $uninstall = "$($env:windir)\ccmsetup\ccmsetup.exe" 
                $switches = "/uninstall"
                $launchLog = "& `"$($PSScriptRoot)\cmtrace.exe`" `"$($env:windir)\ccmsetup\logs\ccmsetup.log`""
            } ElseIf(Test-path "$($PSScriptRoot)\ccmclean.exe" -PathType Leaf) {  
                $uninstall = "$($PSScriptRoot)\ccmclean.exe"
                $switches =  "/logdir:`"$($env:windir)\temp`" /removehistory /q"
                $launchLog = "& `"$($PSScriptRoot)\cmtrace.exe`" `"$($env:windir)\temp\ccmclean.log`""
            } Else {
                #handle no removal code present
                Write-Verbose "$(Get-Date -Format g): Unable to locate neither $($env:windir)\ccmsetup\ccmsetup.exe nor $($PSScriptRoot)\ccmclean.exe." 
                Write-Verbose "$(Get-Date -Format g): Unable to uninstall CCM client. Script exiting."
            }

            Write-Verbose "Running $returnValue = Start-Process -FilePath $($uninstall) -ArgumentList $($switches)  -NoNewWindow -Wait -Passthru"
            $returnValue = Start-Process -FilePath $uninstall -ArgumentList $switches  -NoNewWindow -Wait -Passthru
            Write-Verbose "Exitcode is $($returnValue.ExitCode)"

            Invoke-Expression $launchLog -ErrorAction SilentlyContinue

            If($($returnValue.ExitCode -eq 0) -or $($returnValue.ExitCode -eq 3010)) {
                Write-Verbose "$(Get-Date -Format g): Uninstall successful."
                Write-Verbose "$(Get-Date -Format g): Uninstall: $($uninstall) has ended." 
                Write-Verbose "$(Get-Date -Format g): Please verify executable exit in uninstall log."

                #Stop the Service "ccmsetup" which is also a Process "ccmsetup.exe" if it wasn't stopped in the services after uninstall
                if(!([string]::IsNullOrEmpty((Get-Service -Name ccmsetup -ErrorAction SilentlyContinue).Name))) {
                    Write-Verbose "$(Get-Date -Format g): Killing unexpected ccmsetup process."
                    Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force -Verbose
                }

                #Remove CCM folders in system directory
                Write-Verbose "$(Get-Date -Format g): Removing $($Env:WinDir)\CCM"
                If(Test-Path "$($Env:WinDir)\CCM" -PathType Container) {Remove-Item -Path "$($Env:WinDir)\CCM" -Force -Recurse -Confirm:$false -Verbose}
                Write-Verbose "$(Get-Date -Format g): Removing $($Env:WinDir)\CCMSetup"
                If(Test-Path "$($Env:WinDir)\CCMSetup" -PathType Container) {Remove-Item -Path "$($Env:WinDir)\CCMSetup" -Force -Recurse -Confirm:$false -Verbose}
                Write-Verbose "$(Get-Date -Format g): Removing $($Env:WinDir)\CCMCache"
                If(Test-Path "$($Env:WinDir)\CCMCache" -PathType Container) {Remove-Item -Path "$($Env:WinDir)\CCMCache" -Force -Recurse -Confirm:$false -Verbose}

                #Remove registry keys associated with the SCCM Client that might not be removed by ccmclean.exe
                Write-Verbose "$(Get-Date -Format g): Removing associated CCM registry keys if present"
                Update-Registry('HKLM:\SOFTWARE\Microsoft\CCM')
                Update-Registry('HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM')
                Update-Registry('HKLM:\SOFTWARE\Microsoft\SMS')
                Update-Registry('HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS')
                Update-Registry('HKLM:\Software\Microsoft\CCMSetup')
                Update-Registry('HKLM:\Software\Wow6432Node\Microsoft\CCMSetup')

                #Remove the service from "Services"
                Write-Verbose "$(Get-Date -Format g): Removing ccmexec and ccmsetup services if active."
                Update-Registry('HKLM:\SYSTEM\CurrentControlSet\Services\CcmExec')
                Update-Registry('HKLM:\SYSTEM\CurrentControlSet\Services\ccmsetup')

                #Remove the Namespaces from the WMI repository if present
                Write-Verbose "$(Get-Date -Format g): Removing CCM WMi namspaces on local computer."
                If(Get-CimInstance -class "CCM" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='CCM'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
                If(Get-CimInstance -class "CCMVDI" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
                If(Get-CimInstance -class "SmsDm" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
                If(Get-CimInstance -class "sms" -Namespace "root\cimv2" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" | Remove-CimInstance -Verbose -Confirm:$false}

                If($RemoveAll.IsPresent) {
                    #Delete the file with the certificate GUID and SMS GUID that current Client was registered with
                    Write-Verbose "$(Get-Date -Format g): Removing $($Env:WinDir)\smscfg.ini if present"
                    If(Test-Path "$($Env:WinDir)\smscfg.ini" -PathType Leaf) {Remove-Item -Path "$($Env:WinDir)\smscfg.ini" -Force -Recurse -Confirm:$false -Verbose}
                    #Delete the certificate itself
                    Update-Registry('HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*')
                    #Add webservice call here
                }

                #Add Teams Webhook function here

                #NOMAD cache clean
                If((Get-Command "cachecleaner.exe" -ErrorAction SilentlyContinue) -eq $null){
                    Write-Verbose "$(Get-Date -Format g): Unable to find NOMAD cachecleaner.exe in PATH statement"
                } else {
                    Write-Verbose "$(Get-Date -Format g): Invoking NOMAD cachecleaner.exe"
                    Invoke-Expression "cachecleaner.exe --deleteall" -ErrorAction Stop
                    Wait-Process -Id (Get-Process -name "cachecleaner.exe").Id -Timeout 120
                    Write-Verbose "$(Get-Date -Format g): NOMAD cachecleaner.exe process ended or 120 second timeout reached" 
                }
            } Else {
                Write-Verbose "Something unexpected with the uninstall."
                #Something went wrong with uninstall
            }

        } Catch {
            #error handling go here, $_ contains the error record
            Write-Verbose "$($_.Exception.Message)"
        }
        Write-Verbose "$(Get-Date -Format g): Ending Uninstall-CcmClient function."
}


Uninstall-CcmClient -Verbose -RemoveAll