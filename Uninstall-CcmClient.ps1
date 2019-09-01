#https://www.optimizationcore.com/deployment/sccm-client-complete-remove-uninstall-powershell-script/
FUNCTION Uninstall-CcmClient{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,
                       HelpMessage="Completely remove CCM client")]
                       [switch]$RemoveAll
                   )
    BEGIN {
        Write-Verbose "$(Get-Date -Format g): Beginning BEGIN block. RemoveAll parameter is set to $($RemoveAll)"
        Write-Verbose "$(Get-Date -Format g): Ending BEGIN block. RemoveAll parameter is set to $($RemoveAll)" 
    } #END BEGIN
    PROCESS {
        Write-Verbose "$(Get-Date -Format g): Beginning PROCESS block."
        Try {
            If(Test-Path "$($env:windir)\ccmsetup\ccmsetup.exe" -PathType Leaf){
                $uninstall = "& `"$($env:windir)\ccmsetup\ccmsetup.exe`" /uninstall"
                $launchLog = "& `"$($PSScriptRoot)\cmtrace.exe`" `"$($env:windir)\ccmsetup\logs\ccmsetup.log`""
                $process = "ccmsetup"  
            } ElseIf(Test-path "$($PSScriptRoot)\ccmclean.exe" -PathType Leaf) {  
                $uninstall = "& `"$($PSScriptRoot)\ccmclean.exe`" /logdir:`"$($env:windir)\temp`" /removehistory /q"
                $launchLog = "& `"$($PSScriptRoot)\cmtrace.exe`" `"$($env:windir)\temp\ccmclean.log`""
                $process = "ccmclean"
            } Else {
                #handle no removal code present
                Write-Verbose "$(Get-Date -Format g): Unable to locate neither $($env:windir)\ccmsetup\ccmsetup.exe nor $($PSScriptRoot)\ccmclean.exe." 
                Write-Verbose "$(Get-Date -Format g): Unable to uninstall CCM client. Script exiting."
            }

            Write-Verbose "$(Get-Date -Format g): Invoking uninstall: $($uninstall)"
            Invoke-Expression $uninstall -ErrorAction Stop

            If($($? -eq $true)) {
                Write-Verbose "$(Get-Date -Format g): Uninstall successful? $($?)."
                Invoke-Expression $launchLog -ErrorAction SilentlyContinue
                
                Write-Verbose "$(Get-Date -Format g): Uninstall: $($uninstall) has ended." 
                Write-Verbose "$(Get-Date -Format g): Please verify exit in uninstall log."

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
                Write-Verbose "$(Get-Date -Format g): Removing associated CCM registry keys."
                If(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Force -Recurse -Confirm:$false -Verbose}
                If(Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM') {Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM' -Force -Recurse -Confirm:$false -Verbose}
                If(Test-Path 'HKLM:\SOFTWARE\Microsoft\SMS') {Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\SMS' -Force -Recurse -Verbose}
                If(Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS') {Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS' -Force -Recurse -Confirm:$false -Verbose}
                If(Test-Path 'HKLM:\Software\Microsoft\CCMSetup') {Remove-Item -Path 'HKLM:\Software\Microsoft\CCMSetup' -Force -Recurse -Verbose}
                If(Test-Path 'HKLM:\Software\Wow6432Node\Microsoft\CCMSetup') {Remove-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\CCMSetup' -Force -Recurse -Confirm:$false -Verbose}

                #Remove the service from "Services"
                Write-Verbose "$(Get-Date -Format g): Removing ccmexec and ccmsetup services if active."
                If(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CcmExec' -Force -Recurse -Confirm:$false -Verbose}
                If(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ccmsetup' -Force -Recurse -Confirm:$false -Verbose}

                #Remove the Namespaces from the WMI repository if present
                Write-Verbose "$(Get-Date -Format g): Removing CCM WMi namspaceson local computer."
                If(Get-CimInstance -class "CCM" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='CCM'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
                If(Get-CimInstance -class "CCMVDI" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
                If(Get-CimInstance -class "SmsDm" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
                If(Get-CimInstance -class "sms" -Namespace "root\cimv2" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" | Remove-CimInstance -Verbose -Confirm:$false}

                If($RemoveAll) {
                    #Delete the file with the certificate GUID and SMS GUID that current Client was registered with
                    Remove-Item -Path "$($Env:WinDir)\smscfg.ini" -Force -Confirm:$false -Verbose
                    #Delete the certificate itself
                    Remove-Item -Path 'HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*' -Force -Confirm:$false -Verbose
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
                Write-Verbose "Something unexpected with uninstall."
                #Something went wrong with uninstall
            }

        } Catch {
            #error handling go here, $_ contains the error record
            Write-Verbose "$($_.Exception.Message)"
        }
        Write-Verbose "$(Get-Date -Format g): Ending PROCESS block." 
    }
    END{}
}

Uninstall-CcmClient -Verbose