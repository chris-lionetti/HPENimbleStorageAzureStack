$NimbleUserName = "admin"
$NimblePassword = "admin"
$NimbleArrayIP = "10.1.240.20"
# Do not need to modify anything below this line.
# This single file should NOT be posted to YOUR public Github site as it contains the username and password of the Nimble array
# that you intend to use.
################################################################################################################################
$InitialPull=@'
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
            {   ServicePointManager.ServerCertificateValidationCallback += 
                delegate    (   Object obj, 
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
$uri="https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/NimbleStorageUnattended.ps1"
$Code=(Invoke-WebRequest -Uri $uri -Method Get).content
out-file -FilePath "C:\NimbleStorage\NimbleStorageUnAttended.ps1" -inputobject $Code -ErrorAction SilentlyContinue -force

$RunOnce="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnce "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + 'C:\NimbleStorage\NimbleStorageUnattended.ps1')
write-host "Hit CTRL-C in next 60 seconds to abort the AutoReboot cycle"
start-sleep -Seconds 60
shutdown -t 0 -r -f
'@
mkdir C:\NimbleStorage -ErrorAction SilentlyContinue 
New-Item -Path "HKLM:\Software\AzureStackNimbleStorage"
New-ItemProperty -Path "HKLM:\Software\AzureStackNimbleStorage" -PropertyType String -Name NimbleUserName -Value $NimbleUserName
New-ItemProperty -Path "HKLM:\Software\AzureStackNimbleStorage" -PropertyType String -Name NimblePassword -Value $NimblePassword
New-ItemProperty -Path "HKLM:\Software\AzureStackNimbleStorage" -PropertyType String -Name NimbleArrayIP -Value $NimbleArrayIP
out-file -filepath C:\NimbleStorage\InitialPull.ps1 -inputobject $InitialPull -force
$RunOnce="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnce "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + 'C:\NimbleStorage\InitialPull.ps1')