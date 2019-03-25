

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
$uri='https://raw.githubusercontent.com/chris-lionetti/HPENimbleStorageAzureStack/master/HPENimbleStorage.ps1'

mkdir C:\temp
Get-process | Out-File "C:\temp\MyOutputFile.txt"

$Code=$(Invoke-WebRequest -Uri $uri -Method Get).content
$Code | out-file -FilePath 'C:\temp\MyCode.txt'

$R=Invoke-WebRequest -Uri $uri
$R | Out-File -FilePath 'C:\temp\MyResponse.txt'

