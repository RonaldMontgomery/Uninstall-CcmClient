#https://www.optimizationcore.com/deployment/sccm-client-complete-remove-uninstall-powershell-script/

If(Test-path "$($PSScriptRoot)\ccmclean.exe" -PathType Leaf) {  
    
    Try {
        Invoke-Expression "& `"$($PSScriptRoot)\ccmclean.exe`" /logdir:`"$($env:windir)\temp`" /removehistory /q"
        
        Invoke-Expression "& `"$($PSScriptRoot)\cmtrace.exe`" `"$($env:windir)\temp\ccmclean.log`"" -ErrorAction SilentlyContinue
        Wait-Process -Id (Get-Process -name "ccmclean").Id -Timeout 60

        if([string]::IsNullOrEmpty((Get-Process -name "ccmclean" -ErrorAction Stop).Id)) {

            # Stop the Service "ccmsetup" which is also a Process "ccmsetup.exe" if it wasn't stopped in the services after uninstall
            if(!([string]::IsNullOrEmpty((Get-Service -Name ccmsetup -ErrorAction SilentlyContinue).Name))) {Get-Service -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Service -Force -Verbose}

            #Remove CCM foldrs in system directory
            If(Test-Path "$($Env:WinDir)\CCM" -PathType Container) {Remove-Item -Path "$($Env:WinDir)\CCM" -Force -Recurse -Confirm:$false -Verbose}
            If(Test-Path "$($Env:WinDir)\CCMSetup" -PathType Container) {Remove-Item -Path "$($Env:WinDir)\CCMSetup" -Force -Recurse -Confirm:$false -Verbose}
            If(Test-Path "$($Env:WinDir)\CCMCache" -PathType Container) {Remove-Item -Path "$($Env:WinDir)\CCMCache" -Force -Recurse -Confirm:$false -Verbose}

            # Remove registry keys associated with the SCCM Client that might not be removed by ccmclean.exe
            If(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Force -Recurse -Confirm:$false -Verbose}
            If(Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM') {Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM' -Force -Recurse -Confirm:$false -Verbose}
            If(Test-Path 'HKLM:\SOFTWARE\Microsoft\SMS') {Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\SMS' -Force -Recurse -Verbose}
            If(Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS') {Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS' -Force -Recurse -Confirm:$false -Verbose}
            If(Test-Path 'HKLM:\Software\Microsoft\CCMSetup') {Remove-Item -Path 'HKLM:\Software\Microsoft\CCMSetup' -Force -Recurse -Verbose}
            If(Test-Path 'HKLM:\Software\Wow6432Node\Microsoft\CCMSetup') {Remove-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\CCMSetup' -Force -Recurse -Confirm:$false -Verbose}

            # Remove the service from "Services"
            If(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CcmExec' -Force -Recurse -Confirm:$false -Verbose}
            If(Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ccmsetup' -Force -Recurse -Confirm:$false -Verbose}

            # Remove the Namespaces from the WMI repository if present
            If(Get-CimInstance -class "CCM" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='CCM'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
            If(Get-CimInstance -class "CCMVDI" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
            If(Get-CimInstance -class "SmsDm" -Namespace "root" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false}
            If(Get-CimInstance -class "sms" -Namespace "root\cimv2" -ErrorAction SilentlyContinue) {Get-CimInstance -query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" | Remove-CimInstance -Verbose -Confirm:$false}


            # Delete the file with the certificate GUID and SMS GUID that current Client was registered with
            #Remove-Item -Path "$($Env:WinDir)\smscfg.ini" -Force -Confirm:$false -Verbose
            # Delete the certificate itself
            #Remove-Item -Path 'HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*' -Force -Confirm:$false -Verbose
            #Add webservice call here

            #AddTeams Webhook function here

        } Else {
            #Something went wrong with ccmclean
        }

    } Catch {
        # error handling go here, $_ contains the error record
    } 
}
else {
    #exit script

}