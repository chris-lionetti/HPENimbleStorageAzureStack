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
mkdir C:\NimbleStorage
$Code | out-file -FilePath "C:\NimbleStorage\NimbleStorageUnAttended.ps1"

$RunOnce="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
# set-itemproperty $RunOnce "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + 'C:\NimbleStorage\NimbleStorageUnattended.ps1')