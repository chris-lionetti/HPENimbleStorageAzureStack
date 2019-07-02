#################################################################
# Unattended installation script for connecting AzureStack to to a Nimble Storage Infrastructure.                           #
# This script will automatically create a LOG directoy at C:\NimbleStorage\Logs


# Variable Block
$NWTuri=            'https://github.com/chris-lionetti/HPENimbleStorageAzureStack/raw/master/Setup-NimbleNWT-x64.6.0.1.3252.exe'
$NimblePSTKuri=     'https://github.com/chris-lionetti/HPENimbleStorageAzureStack/raw/master/HPENimblePowerShellToolkit.300.zip'   
$UpdatedPSTKcmd=    'https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/AzureStack.ps1'
$UpdatedPSTK=       'https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/NimPSSDK.psm1'

# No variables below this line need to be modified by the user/consumer of the script
$AZNSoutfile =      "C:\NimbleStorage\Logs\NimbleInstall.log"
$WindowsPowerShellModulePath="C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
$ScriptLocation=    'C:\NimbleStorage\NimbleStorageUnattended.ps1'
$RunOnceValue=      'C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + $ScriptLocation
$RunOnce =          "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$NimbleUser =       (Get-ItemProperty -Path HKLM:\Software\AzureStackNimbleStorage).NimbleUserName
$NimblePassword =   (Get-ItemProperty -Path HKLM:\Software\AzureStackNimbleStorage).NimblePassword
$NimbleArrayIP =    (Get-ItemProperty -Path HKLM:\Software\AzureStackNimbleStorage).NimbleArrayIP

function Post-AZNSEvent([String]$AZNSTextField, [string]$AZNSEventType)
{   # Subroutine to Post Events to Log/Screen/EventLog
    switch -wildcard ($Eventtype)
        {   "Info*"     { $AZNScolor="gray" }
            "Warn*"     { $AZNScolor="green" }
            "Err*"      { $AZNScolor="yellow" }
            "Cri*"      { $AZNScolor="red"
                          $AZNSEventType="Error" }
            default     { $AZNScolor="gray" }
        }
    write-host "- "$AZNStextfield -foregroundcolor $AZNScolor
    $AZNSTextField | out-file -filepath $AZNSoutfile -append
} 
function Set-NSASSecurityProtocolOverride
{   # Will override the behavior of Invoke-WebRequest to allow access without a Certificate. 
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {   $certCallback = @"
            using System;
            using System.Net;
            using System.Net.Security;
            using System.Security.Cryptography.X509Certificates;
            public class ServerCertificateValidationCallback
            {   public static void Ignore()
                {   if(ServicePointManager.ServerCertificateValidationCallback ==null)
                    {   ServicePointManager.ServerCertificateValidationCallback += delegate (   Object obj, 
                                                                                                X509Certificate certificate, 
                                                                                              X509Chain chain, 
                                                                                             SslPolicyErrors errors
                                                                                           )
                        {   return true;
                        };
                    }
                }
            }
"@
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
}
function Load-NimblePSTKModules
{   # Loads the Nimble PowerShell Toolkit from the GitHub Site identifed in the Global Variables
    if ( Test-Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\HPENimblePowerShellToolkit' -PathType Container )
    {   Post-AZNSEvent "The HPE NimbleStorage PowerShell Toolkit is installed" "Info"
    } else 
    {   Post-AZNSEvent "Now Installing the Nimble PowerShell Toolkit" "Warning"
        invoke-webrequest -uri $NimblePSTKuri -outfile "C:\NimbleStorage\HPENimblePowerShellToolkit.300.zip"
        $PSMPath="C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
        expand-archive -path "C:\NimbleStorage\HPENimblePowerShellToolkit.300.zip" -DestinationPath $WindowsPowerShellModulePath

        Post-AZNSEvent "Now Changing the Nimble Powershell toolkit to add the AzureStack command" "Warning"
        invoke-webrequest -uri $UpdatedPSTK -outfile "C:\NimbleStorage\NimPSSDK.psm1"
        $AZNSRoot=$PSMPath+"\HPENimblePowerShellToolkit"
        Copy-item -path 'C:\NimbleStorage\NimPSSDK.psm1' -destination $AZNSRoot -force

        Post-AZNSEvent "Now adding the AzureStack Command" "Warning"
        invoke-webrequest -uri $UpdatedPSTKcmd -outfile "C:\NimbleStorage\AzureStack.ps1"
        $AZNSScripts=$AZNSRoot+"\scripts"
        Copy-item -path 'C:\NimbleStorage\AzureStack.ps1' -Destination $AZNSScripts -force

    }
}
function Load-WindowsMPIOFeature
{   # Load the Windows MPIO feature. Returns True if a Reboot is required.
    if( (get-WindowsFeature -name "Multipath-io").installed )
    {   Post-AZNSEvent "The Windows Multipath IO Feature is already Installed" "Information"
        if ( (get-windowsFeature -name "Multipath-io").InstallState -ne "Installed")
            {   Post-AZNSEvent "Reboot is required after a Windows Multipath IO Feature Installation" "Warning"
                $ForceReboot=$True
                return $True
            } else 
            {   Post-AZNSEvent "The Windows Multipath IO Feature does not require a reboot" "Information"
                return $false                
            }
    } else 
    {  # Step 1a Install MPIO if not installed
        add-WindowsFeature -name "Multipath-io"
        Post-AZNSEvent "The Windows Multipath IO Feature is not installed, Installing Now!" "Warning"
        Post-AZNSEvent "Reboot is required after a Windows Multipath IO Feature Installation" "Warning"
        $ForceReboot=$True
        return $true
    }
}
function Load-NWTPackage
{   # Download and instlal the Nimble Windows Toolkit. If already installed, return false, otherwise install and request a reboot.
    if ($ForceReboot)
    {   Post-AZNSEvent "The Nimble Windows Toolkit Cannot install since reboot is pending" "warning"
        return $ForceReboot 
    }
    else
    {   $NWTsoftware="Nimble Windows Toolkit"
        $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq 'Nimble Windows Toolkit' }) -ne $null
        if ($installed)
        {   Post-AZNSEvent "The Nimble Windows Toolkit is already installed" "Information"
            return $false
        } else
        {   # If NWT not installed, silent install it
            invoke-webrequest -uri $NWTuri -outfile "C:\NimbleStorage\Setup-NimbleNWT-current.exe"
            $NWTEXE = "C:\NimbleStorage\Setup-NimbleNWT-current.exe"
            $NWTArg1 = "EULAACCEPTED=Yes"
            $NWTArg2 = "HOTFIXPASS=Yes"
            $NWTArg3 = "RebootYesNo=Yes"
            $NWTArg4 = "NIMBLEVSSPORT=Yes"
            $NWTArg5 = "/silent"
            & $NWTEXE $NWTArg1 $NWTArg2 $NWTArg3 $NWTArg4 $NWTArg5
            # Invoke-Command -ScriptBlock "C:\NimbleStorage\Setup-NimbleNWTx64.0.0.0.XXX.exe EULAACCEPTED=Yes HOTFIXPASS=Yes RebootYesNo=Yes NIMBLEVSSPORT=Yes /silent"
            Post-AZNSEvent "Initiating download and Silent Installation of the Nimble Windows Toolkit" "Warning"
            return $true
        }
    }
}
function Configure-AZNSiSCSI
{   # Will start the ISCSI service, and configure it to connect to the Nimble Array
    Start-Service msiscsi
    Set-Service msiscsi -startuptype "automatic"
    Post-AZNSEvent "Ensuring that the iSCSI Initiator Service is started, and setting it to start automatically" "Warning"
    new-iSCSITargetPortal -TargetPortalAddress $NimbleArrayIP
}
function Create-AZNSNimbleInitiatorGroups
{   # The Autogenerated Initiator Group will be named for the servers hostname
    $MyLocalIQN=(Get-InitiatorPort | where-object {$_.ConnectionType -like "iSCSI"} ).nodeaddress
    Import-Module HPENimblePowerShellToolkit
    if (Test-NSNimbleWindowsToolkitInstalledConfigured)
    {   Connect-AzNSGroup -UserNWTCredentials $true -IgnoreServerCertificate
        if (Get-NSDisk)
        {   Post-AZNSEvent "Was able to Successfully Connect to the array using the supplied Credentials" "Info"
            if (-not (Get-NSInitiatorGroup -name (hostname) ) )
            {   New-NSInitiatorgroup -name (hostname) -description "Automatically Created using Scripts" -access_protocol "iscsi"
                Post-AZNSEvent "Created new Initiator Group for this host" "Info"
            } else 
            {   Post-AZNSEvent "Initiator Group already found for this hostname" "Info"
            }
            $NSIGID=(Get-NSInitiatorGroup -name (hostname) ).id
            $Label = (hostname)+"-Autocreated"
            if ( -not ( get-NSInitiator -label $Label ) )
                {   New-NSInitiator -initiator_group_id $NSIGID -access_protocol "iscsi" -iqn $MyLocalIQN -label $Label
                    Post-AZNSEvent "Created new Initiator for this Initiator Group" "Info"
                } else 
                {   Post-AZNSEvent "Initiator Group already found for this hostname" "Info"
                }
        } else
        {   Post-AZNSEvent "Was Unable to connect to the Nimble Array using the Supplied Credentials" "Error"
        }
    } else 
    {   Post-AZNSEvent "NWT was not installed or configured, will setup initiators on next reboot" "Warning"
    }
}

function Setup-AZNSNimbleWindowsToolkit
{   #Configure the NWT with the supplied Username and Password.
    $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq 'Nimble Windows Toolkit' }) -ne $null
    if ($installed)
        {   set-location -path 'C:\Program Files\Nimble Storage\Bin\'
            import-module 'C:\Program Files\Nimble Storage\Bin\Nimble.PowerShellCmdlets.psd1'
            set-location -Path 'C:\nimbleStorage'
            if ( Get-NWTConfiguration | where{$_.GroupMgmtIPList -ne ""} )
                {   Post-AZNSEvent "The Nimble Windows Toolkit has already been configured" "info"
                } else 
                {   $NimblePasswordObect = ConvertTo-SecureString $NimblePassword -AsPlainText -force
                    $NimbleCredObject = new-object -typename System.Management.Automation.PSCredential -argumentlist $NimbleUser, $NimblePasswordObect
                    set-nwtconfiguration -groupmgmtip $NimbleArrayIP -Credential $NimbleCredObject
                    Post-AZNSEvent "The Nimble Windows Toolkit has been Configured" "info"
                }
        } 
}

##########################################################################
# MAIN Unattended Installation Script for Nimble Storag on Azure Stack.  #
Set-NSASSecurityProtocolOverride
Load-NimblePSTKModules
Configure-AZNSiSCSI
Create-AZNSNimbleInitiatorGroups
$ForceReboot=Load-WindowsMPIOFeature
$ForceReboot=Load-NWTPackage
Setup-AZNSNimbleWindowsToolkit
if ($ForceReboot)
    {   set-itemproperty -path $RunOnce "NextRun" $RunOnceValue
        Post-AZNSEvent "This Installation Script is set to run again once the server has been rebooted. Please Reboot this server" "Warning"
    } else 
    {   if (Get-ItemProperty -Path $RunOnce) 
            {   remove-itemproperty -path $RunOnce "NextRun"
                Post-AZNSEvent "This script will NOT be re-run on reboot" "warning"        
            }
        Post-AZNSEvent "This Script has verified that all required software is installed, and that no reboot is needed" "Information"     
    }
if ($ForceReboot)
    {   write-host "Hit CTRL-C in next 60 seconds to abort the AutoReboot cycle"
        start-sleep -Seconds 60
        shutdown -t 0 -r -f
    }
    