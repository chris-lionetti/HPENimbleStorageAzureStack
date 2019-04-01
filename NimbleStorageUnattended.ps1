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

$uri='https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/HPENimbleStorage.ps1'
$ForceReboot=$False
$DidSomething=$False
# Step 0 If Nimble PSTK not downloaded download it
if ( Test-Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\HPENimblePowerShellToolkit' -PathType Container )
    {   write-host "The HPE NimbleStorage PowerShell Toolkit is installed"
    } else 
    {   $DidSomething=$True
        $uri='https://github.com/chris-lionetti/HPENimbleStorageAzureStack/raw/master/HPENimblePowerShellToolkit.210.zip'
        invoke-webrequest -uri $uri -outfile "C:\temp\HPENimblePowerShellToolkit.210.zip"
        $PSMPath="C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
        expand-archive -path "C:\temp\HPENimblePowerShellToolkit.210.zip" -DestinationPath $PSMPath
    }

# step 0b Use secrets to discover array and log into array 

# Step 1 Detect if MPIO is installed
if( (get-WindowsFeature -name "Multipath-io").installed )
    {   write-host "MPIO is installed"
        if ( (get-windowsFeature -name "Multipath-io").InstallState -ne "Installed")
            {   write-host "Reboot is required"
                $ForceReboot=$True
            }
    } else 
    {  # Step 1a Install MPIO if not installed
        add-WindowsFeature -name "Multipath-io"
        write-host "Initiated a installation of the Windows Multipath-io feature. "
        write-host "This server will need to reboot before it is complete"
        $ForceReboot=$True
        $DidSomething=$True
    }
# Step 2 If NWT not downloaded, download it
if ( -not $ForceReboot )
{   $software="Nimble Windows Toolkit"
    $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $software }) -ne $null
    if ($installed)
    {   write-host 'Nimble Windows Toolkit has been installed'
    } else
    {   # Step 2a If NWT not installed, silent install it
        $uri='https://github.com/chris-lionetti/HPENimbleStorageAzureStack/raw/master/Setup-NimbleNWT-x64.5.0.0.7991.exe'
        invoke-webrequest -uri $uri -outfile "C:\temp\Setup-NimbleNWT-x64.5.0.0.7991.exe"
        Invoke-Command -ScriptBlock "C:\temp\Setup-NimbleNWTx64.0.0.0.XXX.exe EULAACCEPTED=Yes HOTFIXPASS=Yes RebootYesNo=Yes NIMBLEVSSPORT=Yes /silent"
        write-host "Did a silent install of the Nimble Windows Toolkit"
        $DidSomething=$True
        $ForceReboot=$True
    }
}
if ($DidSomething -or $ForceReboot)
    {   $RunOnce="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        set-itemproperty $RunOnce "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + 'C:\temp\NimbleStorageUnattended.ps1')
        write-host "Set the script to run on the next reboot"
        write-host "PLease Reboot the server"
    } else 
    {   write-host "No actions were needed and reboot not needed"
        write-host "Script NOT set to rerun on next boot."
    
    }
