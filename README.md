# HPENimbleStorageAzureStack
HPE Nimble Storage Integration with HPE AzureStack

The following files are used in the following ways.

AzureStack.ps1  : This file is an additional set of commands for the default nimble PowerShell Toolkit, It is installed in the same modules directory that the powershell toolkit gets installed. These are commands specifically written to assist Azure Stack installations. The prerequisite for this file is that the PowerShell Toolkit is already installed.
HPENimblePowerShell.ps1 : This is the AzureStack VM Extention file. This is the only file that you need to manually download and is the file that is used in the AzureStack Portal which will let each VM pull the rest of the files manually. You will need to modify this file to point to YOUR github location once you have modified the default password/username/etc.
HPENimblePowerShellToolkit.300.zip : This is a copy directly from Infosight of the PowerShell Toolkit for Nimble. The VM Extensions are unable to log into a secure website like Infosight to grab these files, so they have been placed in the Github location to make retrieval easy.
NimbleStorageUnattended.ps1 : This is the file with all of the unattended actions that need to be completed on each server. This file will be downloaded an autoexecuted at the direction of the VM Extension. You will also need to modify a few default settings in this file such as username, IP address, and password for the Nimble Array.
Setup-NimbleNWT-x64.6.0.1.3252.zip : This is a copy directly from Infosight of the Nimble Windows Toolkit. he VM Extensions are unable to log into a secure website like Infosight to grab these files, so they have been placed in the Github location to make retrieval easy.
NimPSSDK.psm1 : This is the new copy of the Nimble PowerShell Toolkit Manifest that includes the new commands listed in the AzureStack extention. This will overwrite the existing manifest in the existing Nimble PowerShell Toolkit, so the prerequisite is that the Nimble PowerShell toolkit is already installed.
