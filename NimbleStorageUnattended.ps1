#################################################################
# Unattended installation script for connecting AzureStack to   #
# to a Nimble Storage Infrastructure.                           #
#                                                               #
# All functions use the Verb-Nouns contruct, but the Noun is    #
# always preceeded by AZNS which stands for AzureStack Nimble   #
# Storage. This prevents collisions in customer enviornments    #                                                      
#                                                               #
# Additionally, this script will automatically create a LOG     #
# directoy at C:\NimbleStorage\Logs and will also post to the   #
# Windows Event Logs.                                           #
#                                                               #
# Published https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/NimbleStorageUnattended.ps1
# Written by Chris Lionetti                                     #
#################################################################

# Variable Block
$NWTuri=            'https://github.com/chris-lionetti/HPENimbleStorageAzureStack/raw/master/Setup-NimbleNWT-x64.5.0.0.7991.exe'
$NimblePSTKuri=     'https://github.com/chris-lionetti/HPENimbleStorageAzureStack/raw/master/HPENimblePowerShellToolkit.300.zip'   
$WindowsPowerShellModulePath="C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
$NimbleArrayIP=     "10.1.240.20"
$NimbleUser=        "admin"
$NimblePassword=    "admin"
$AZNSoutfile =      "C:\NimbleStorage\Logs\NimbleInstall.log"
$RunOnce=           "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$ScriptLocation=    'C:\NimbleStorage\NimbleStorageUnattended.ps1'
$RunOnceValue=      'C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + $ScriptLocation
$UpdatedPSTKcmd=    'https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/AzureStack.ps1'
$UpdatedPSTK=       'https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/NimPSSDK.psm1'

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
    Write-Eventlog -LogName Application -Source NimbleStorage -EventID 1 -Message $AZNSTextField -EntryType $AZNSEventType -Computername "." -category 0
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
function Setup-ASNSLogEvents([String] $AZNSaction, [String]$AZNSStep )
{   # Valid options for the action are either "StartLog" or "EndLog" or defining a step number
    if ( $AZNSaction -like "StartLog")
        {   # Create the location for the log file
            if (! (test-path $AZNSoutfile))
                {   mkdir c:\NimbleStorage -erroraction SilentlyContinue
                    mkdir c:\NimbleStorage\Logs -erroraction SilentlyContinue
                }
            # This banner makes it easier to parse the log file later quickly.
            "##########################################################" | out-file -filepath $AZNSoutfile -append
            "################### Starting New Run #####################" | out-file -filepath $AZNSoutfile -append
            if (! (test-path HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\application\NimbleStorage) )
                {   # if the eventlog catagory doesnt exist, need to register it
                    New-Eventlog -LogName Application -source NimbleStorage
                    Post-AZNSEvent "Creating Eventlog\Application\NimbleStorage Eventlog Source" "Warning"
                }
        }
    if ( $AZNSaction -like "EndLog")
        {   "################### Ending Run #####################" | out-file -filepath $AZNSoutfile -append
            "####################################################" | out-file -filepath $AZNSoutfile -append
        }
    if ( $AZNSAction -like "Step")
        {   "# Now Executing Step "+$AZNSStep | out-file -filepath $AZNSoutfile -append

        }
}
function Load-NSASAzureModules
{   # Loads all of the Nimble Storage Azure Stack specific PowerShell Modules
    if (-not (get-Module -name AzureRM.Storage -ErrorAction SilentlyContinue) )
    {   Post-AZNSEvent "The required AzureStack Powershell are being Installed" "Info"
        Install-Packageprovider -name NuGet -MinimumVersion 2.8.5.201 -force
            Post-AZNSEvent "Install-Packageprovider -name NuGet -MinimumVersion 2.8.5.201" "Info"
        Set-PSRepository -name "PSGallery" -InstallationPolicy Trusted
            Post-AZNSEvent "Set-PSRepository -name PSGallery -InstallationPolicy Trusted" "Info"
        Import-Module -Name PowerShellGet
            Post-AZNSEvent "Import-Module -Name PowerShellGet" "Info"
        Set-PSRepository -name "PSGallery" -InstallationPolicy Trusted
            Post-AZNSEvent "Set-PSRepository -name PSGallery -InstallationPolicy Trusted" "info"
        Import-Module -Name PackageManagement  
            Post-AZNSEvent "Import-Module -Name PackageManagement" "Info"
        Register-PsRepository -Default -ErrorAction SilentlyContinue
            Post-AZNSEvent "Register-PsRepository -Default -ErrorAction SilentlyContinue" "Info"
        register-psrepository -default -ErrorAction SilentlyContinue
            Post-AZNSEvent "register-psrepository -default -ErrorAction SilentlyContinue" "Info"
        install-module AzureRM -RequiredVersion 2.4.0
            Post-AZNSEvent "install-module AzureRM -RequiredVersion 2.4.0" "Info"
        Install-Module -name AzureStack -RequiredVersion 1.7.1
            Post-AZNSEvent "Install-Module -name AzureStack -RequiredVersion 1.7.1" "Info"
        # Install the Azure.Storage module version 4.5.0
        Install-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Force -AllowClobber
            Post-AZNSEvent "Install-Module -Name Azure.Storage -RequiredVersion 4.5.0 -Force -AllowClobber" "Info"
        # Install the AzureRm.Storage module version 5.0.4
        Install-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Force -AllowClobber
            Post-AZNSEvent "Install-Module -Name AzureRM.Storage -RequiredVersion 5.0.4 -Force -AllowClobber" "Info"
        # Remove incompatible storage module installed by AzureRM.Storage
        Uninstall-Module Azure.Storage -RequiredVersion 4.6.1 -Force
            Post-AZNSEvent "Uninstall-Module Azure.Storage -RequiredVersion 4.6.1 -Force" "Info"
        # Load the modules explicitly specifying the versions
        Import-Module -Name Azure.Storage -RequiredVersion 4.5.0
            Post-AZNSEvent "Import-Module -Name Azure.Storage -RequiredVersion 4.5.0" "Info"
        Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4
            Post-AZNSEvent "Import-Module -Name AzureRM.Storage -RequiredVersion 5.0.4" "Info"
    } else 
    {   Post-AZNSEvent "The required AzureStack Powershell Modules have been detected" "Info"        
    }
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
    {   Post-AZNSEvent "The Windows Multipath IO Feature is already Insatlled" "Information"
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
        $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $NWTsoftware }) -ne $null
        if ($installed)
        {   Post-AZNSEvent "The Nimble Windows Toolkit is already installed" "Information"
            return $false
        } else
        {   # If NWT not installed, silent install it
            invoke-webrequest -uri $NWTuri -outfile "C:\NimbleStorage\Setup-NimbleNWT-x64.5.0.0.7991.exe"
            $NWTEXE = "C:\NimbleStorage\Setup-NimbleNWT-x64.5.0.0.7991.exe"
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
    $MyNimUsername=(Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\DefaultCred).UserName
    Post-AZNSEvent $MyNimUsername+" is the Useranme" "Info"
    $MyNimPassword=(Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\DefaultCred).Password
    Post-AZNSEvent $MyNimPassword+" is the Password" "Info"
    $NimblePasswordObect = ConvertTo-SecureString $MyNimPassword -AsPlainText -force
    $NimbleCredObject = new-object -typename System.Management.Automation.PSCredential -argumentlist $MyNimUsername, $NimblePasswordObect
    Import-Module HPENimblePowerShellToolkit
    Connect-NSGroup -Group $NimbleArrayIP -Credential $NimbleCredObject -IgnoreServerCertificate
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
}
function Store-AZNSCreds
{   # Create the Registry Entries where the Credentials can be stored. Only available to 'this user'
    If (! (Test-Path "HKCU:\Software\NimbleStorage\Credentials" -ErrorAction SilentlyContinue) )
        {   Write-Host -ForegroundColor Red "Credentials Path Not Found."
            New-Item -Path "HKCU:\Software\NimbleStorage" -Name "Credentials" -Force
            Post-AZNSEvent "Creating Registry Key to store credentials at HKCU:\Software\NimbleStorage\Credentials" "Info"
        }
    if (! (Test-Path "HKCU:\Software\NimbleStorage\Credentials\DefaultCred") )
        {   New-Item -Path HKCU:\Software\NimbleStorage\Credentials\DefaultCred
            Post-AZNSEvent "Creating Registry Key to store credentials at HKCU:\Software\NimbleStorage\Credentials\DefaultCred" "Info"
        }   
    if (! (Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\NimbleStorage\DefaultCred -name UserName -ErrorAction SilentlyContinue) )
        {   New-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\DefaultCred -PropertyType String -Name UserName -Value $NimbleUser -ErrorAction SilentlyContinue
            Post-AZNSEvent "Storing credential username under HKCU:\Software\NimbleStorage\Credentials\DefaultCred" "Info"
        }    
    if (! (Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\NimbleStorage\DefaultCred -name Password -ErrorAction SilentlyContinue) )
        {   New-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\DefaultCred -PropertyType String -Name Password -Value $NimblePassword -ErrorAction SilentlyContinue
            Post-AZNSEvent "Storing credential password under HKCU:\Software\NimbleStorage\Credentials\DefaultCred" "Info"
        } 
    if (! (Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\NimbleStorage\DefaultCred -name IPAddress -ErrorAction SilentlyContinue) )
        {   New-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\DefaultCred -PropertyType String -Name IPAddress -Value $NimbleArrayIP -ErrorAction SilentlyContinue
            Post-AZNSEvent "Storing credential IP Address under HKCU:\Software\NimbleStorage\Credentials\DefaultCred" "Info"
        } 
    Post-AZNSEvent "To obtain username use Username = (Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\NimbleStorage\DefaultCred).UserName" "Info"
    Post-AZNSEvent "To obtain password use Password = (Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\NimbleStorage\DefaultCred).Password" "Info"
    Post-AZNSEvent "To obtain password use IPAddress= (Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\NimbleStorage\DefaultCred).IPAddress" "Info"
}
function Setup-AZNSNimbleWindowsToolkit
{   #Configure the NWT with the supplied Username and Password.
    $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $NWTsoftware }) -ne $null
    if ($installed)
        {   cd "C:\Program Files\Nimble Storage\Bin\"
            import-module "C:\Program Files\Nimble Storage\Bin\Nimble.PowerShellCmdlets.psd1"
            cd "c:\nimbleStorage"
            if ( Get-NWTConfiguration | where{$_.GroupMgmtIPList -ne ""} )
                {   Post-AZNSEvent "The Nimble Windows Toolkit has already been configured" "info"
                } else 
                {   $MyNimUsername=(Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\DefaultCred).UserName
                    Post-AZNSEvent $MyNimUsername+" is the Useranme" "Info"
                    $MyNimPassword=(Get-ItemProperty -Path HKCU:\Software\NimbleStorage\Credentials\DefaultCred).Password
                    Post-AZNSEvent $MyNimPassword+" is the Password" "Info"
                    $NimblePasswordObect = ConvertTo-SecureString $MyNimPassword -AsPlainText -force
                    $NimbleCredObject = new-object -typename System.Management.Automation.PSCredential -argumentlist $MyNimUsername, $NimblePasswordObect
                    set-nwtconfiguration -groupmgmtip $NimbleArrayIP -Credential $NimbleCredObject
                    Post-AZNSEvent "The Nimble Windows Toolkit has been Configured" "info"
                }
        } 
}

#####################################################################################################################################################
# MAIN Unattended Installation Script for Nimble Storag on Azure Stack.                                                                             #
#####################################################################################################################################################
# Set the Global Variables needed for the script to operate
    
# Step 1. Lets Add a Header to the Log File
    Setup-ASNSLogEvents Startlog
    Setup-ASNSLogEvents Step 1
# Step 2. Load the Azure Stack Specific PowerShell modules
    Setup-ASNSLogEvents Step 2
    Load-NSASAzureModules 
# Step 3. All all Invoke-Web* commands to operate without a certificate. 
    Setup-ASNSLogEvents Step 3
    Set-NSASSecurityProtocolOverride
# Step 4. Download and install the Nimble PowerShell Toolkit
    Setup-ASNSLogEvents Step 4
    Load-NimblePSTKModules
# Step 5. Store the Credentials to the array for future automation.
    Setup-ASNSLogEvents Step 5
    Store-AZNSCreds
# Step 6. Ensure that iSCSI is started; 
    Setup-ASNSLogEvents Step 6
    Configure-AZNSiSCSI
# Step 7. Configure the Nimble Array to have the correct Initiator Group and Initiator    
    Setup-ASNSLogEvents Step 7
    Create-AZNSNimbleInitiatorGroups
# Step 8. Detect if MPIO is installed. If it needs reboot, set the flag as the return
    Setup-ASNSLogEvents Step 8
    $ForceReboot=Load-WindowsMPIOFeature
# Step 9. If NWT not downloaded, download it. If it is downloaded and installed require reboot, otherwise to do not set reboot flag
    Setup-ASNSLogEvents Step 9
    $ForceReboot=Load-NWTPackage
# Step 10. Configur the NWT using PowerShell
    Setup-ASNSLogEvents Step 10
    Setup-AZNSNimbleWindowsToolkit
# Step A. If the ForceReboot flag is set, make this script run at the next reboot, otherise exit successfully/complete.
    Setup-ASNSLogEvents Step 11
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
    Setup-ASNSLogEvents Endlog 
    if ($ForceReboot)
        {   write-host "Hit CTRL-C in next 60 seconds to abortt the AutoReboot cycle"
            start-sleep -Seconds 60
            shutdown -t 0 -r -f
        }
    