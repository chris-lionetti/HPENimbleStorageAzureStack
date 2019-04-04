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

function PostEvent([String]$TextField, [string]$EventType)
{   # Subroutine to Post Events to Log/Screen/EventLog
    $outfile = "C:\NimbleStorage\Logs\NimbleInstall.log" 
    if (! (test-path $outfile))
        {   $suppress = mkdir c:\NimbleStorage
            $suppress = mkdir c:\NimbleStorage\Logs
        }
    if (! (test-path HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\application\NimbleStorage) )
        {   New-Eventlog -LogName Application -source NimbleStorage
            PostEvent "Creating Eventlog\Application\NimbleStorage Eventlog Source" "Warning"
        } else
        {   switch -wildcard ($Eventtype)
                {   "Info*"     { $color="gray" }
                    "Warn*"     { $color="green" }
                    "Err*"      { $color="yellow" }
                    "Cri*"      { $color="red"
                                  $EventType="Error" }
                    default     { $color="gray" }
                }
            if (!(!($verbose) -and ($EventType -eq "Information")))
                {   write-host "- "$textfield -foregroundcolor $color
                    Write-Eventlog -LogName Application -Source NimbleStorage -EventID 1 -Message $TextField -EntryType $EventType -Computername "." -category 0
                    $testfield | out-file -filepath $outfile -append
                }
        }
} 

$uri='https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/HPENimbleStorage.ps1'
$ForceReboot=$False
$DidSomething=$False
# Step 0 If Nimble PSTK not downloaded download it
if ( Test-Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\HPENimblePowerShellToolkit' -PathType Container )
    {   PostEvent "The HPE NimbleStorage PowerShell Toolkit is installed" "Information"
    } else 
    {   PostEvent "Now Installing the Nimble PowerShell Toolkit" "Warning"
        $DidSomething=$True
        $uri='https://github.com/chris-lionetti/HPENimbleStorageAzureStack/raw/master/HPENimblePowerShellToolkit.210.zip'
        invoke-webrequest -uri $uri -outfile "C:\temp\HPENimblePowerShellToolkit.210.zip"
        $PSMPath="C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
        expand-archive -path "C:\temp\HPENimblePowerShellToolkit.210.zip" -DestinationPath $PSMPath
    }

# step 0b Use secrets to discover array and log into array 

# Step 1 Detect if MPIO is installed
if( (get-WindowsFeature -name "Multipath-io").installed )
    {   PostEvent "The Windows Multipath IO Feature is already Insatlled" "Information"
        if ( (get-windowsFeature -name "Multipath-io").InstallState -ne "Installed")
            {   PostEvent "Reboot is required after a Windows Multipath IO Feature Installation" "Warning"
                $ForceReboot=$True
            }
    } else 
    {  # Step 1a Install MPIO if not installed
        add-WindowsFeature -name "Multipath-io"
        PostEvent "The Windows Multipath IO Feature is not installed, Installing Now!" "Warning"
        PostEvent "Reboot is required after a Windows Multipath IO Feature Installation" "Warning"
        $ForceReboot=$True
        $DidSomething=$True
    }
# Step 2 If NWT not downloaded, download it
if ( -not $ForceReboot )
{   $software="Nimble Windows Toolkit"
    $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $software }) -ne $null
    if ($installed)
    {   PostEvent "The Nimble Windows Toolkit is already installed" "Information"
    } else
    {   # Step 2a If NWT not installed, silent install it
        $uri='https://github.com/chris-lionetti/HPENimbleStorageAzureStack/raw/master/Setup-NimbleNWT-x64.5.0.0.7991.exe'
        invoke-webrequest -uri $uri -outfile "C:\temp\Setup-NimbleNWT-x64.5.0.0.7991.exe"
        Invoke-Command -ScriptBlock "C:\temp\Setup-NimbleNWTx64.0.0.0.XXX.exe EULAACCEPTED=Yes HOTFIXPASS=Yes RebootYesNo=Yes NIMBLEVSSPORT=Yes /silent"
        PostEvent "Initiating download and Silent Installation of the Nimble Windows Toolkit" "Warning"
        $DidSomething=$True
        $ForceReboot=$True
    }
}
if ($DidSomething -or $ForceReboot)
    {   $RunOnce="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        set-itemproperty $RunOnce "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + 'C:\temp\NimbleStorageUnattended.ps1')
        PostEvent "This Installation Script is set to run again once the server has been rebooted. Please Reboot this server" "Error"
    } else 
    {   PostEvent "This Script has verified that all required software is installed, and that no reboot is needed" "Information"
        PostEvent "This script will not be re-run on reboot" "warning"        
    }
