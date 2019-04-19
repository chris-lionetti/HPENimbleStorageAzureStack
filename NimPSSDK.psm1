. $PSScriptRoot\scripts\helpers.ps1
. $PSScriptRoot\scripts\VolumeCollection.ps1
. $PSScriptRoot\scripts\AccessControlRecord.ps1
. $PSScriptRoot\scripts\Token.ps1
. $PSScriptRoot\scripts\UserGroup.ps1
. $PSScriptRoot\scripts\ChapUser.ps1
. $PSScriptRoot\scripts\Witness.ps1
. $PSScriptRoot\scripts\Pool.ps1
. $PSScriptRoot\scripts\FibreChannelInitiatorAlias.ps1
. $PSScriptRoot\scripts\ProtectionTemplate.ps1
. $PSScriptRoot\scripts\InitiatorGroup.ps1
. $PSScriptRoot\scripts\Snapshot.ps1
. $PSScriptRoot\scripts\Volume.ps1
. $PSScriptRoot\scripts\ActiveDirectoryMembership.ps1
. $PSScriptRoot\scripts\Subnet.ps1
. $PSScriptRoot\scripts\SpaceDomain.ps1
. $PSScriptRoot\scripts\Group.ps1
. $PSScriptRoot\scripts\ReplicationPartner.ps1
. $PSScriptRoot\scripts\Folder.ps1
. $PSScriptRoot\scripts\NetworkConfig.ps1
. $PSScriptRoot\scripts\Controller.ps1
. $PSScriptRoot\scripts\ProtectionSchedule.ps1
. $PSScriptRoot\scripts\MasterKey.ps1
. $PSScriptRoot\scripts\Event.ps1
. $PSScriptRoot\scripts\ApplicationServer.ps1
. $PSScriptRoot\scripts\FibreChannelPort.ps1
. $PSScriptRoot\scripts\ApplicationCategory.ps1
. $PSScriptRoot\scripts\AuditLog.ps1
. $PSScriptRoot\scripts\Initiator.ps1
. $PSScriptRoot\scripts\Version.ps1
. $PSScriptRoot\scripts\PerformancePolicy.ps1
. $PSScriptRoot\scripts\Job.ps1
. $PSScriptRoot\scripts\Disk.ps1
. $PSScriptRoot\scripts\NetworkInterface.ps1
. $PSScriptRoot\scripts\UserPolicy.ps1
. $PSScriptRoot\scripts\SoftwareVersion.ps1
. $PSScriptRoot\scripts\SnapshotCollection.ps1
. $PSScriptRoot\scripts\FibreChannelConfig.ps1
. $PSScriptRoot\scripts\User.ps1
. $PSScriptRoot\scripts\Shelf.ps1
. $PSScriptRoot\scripts\ProtocolEndpoint.ps1
. $PSScriptRoot\scripts\FibreChannelInterface.ps1
. $PSScriptRoot\scripts\FibreChannelSession.ps1
. $PSScriptRoot\scripts\Array.ps1
. $PSScriptRoot\scripts\Alarm.ps1
. $PSScriptRoot\scripts\AzureStack.ps1

Export-ModuleMember -Function Test-NS2PasswordFormat,   Test-Ns2Type,   Test-NS2ID,     Connect-NSGroup,  Disconnect-NSGroup,   IgnoreServerCertificate,
    New-NSVolumeCollection,    Get-NSVolumeCollection,    Set-NSVolumeCollection,    Remove-NSVolumeCollection,   
    Invoke-NSVolumeCollectionPromote,    Invoke-NSVolumeCollectionDemote,    Start-NSVolumeCollectionHandover,    Stop-NSVolumeCollectionHandover,   
    Test-NSVolumeCollection,    New-NSAccessControlRecord,    Get-NSAccessControlRecord,    Remove-NSAccessControlRecord,   
    New-NSToken,    Get-NSToken,    Remove-NSToken,    Get-NSTokenUserDetails,   
    New-NSUserGroup,    Get-NSUserGroup,    Set-NSUserGroup,    Remove-NSUserGroup,   
    New-NSChapUser,    Get-NSChapUser,    Set-NSChapUser,    Remove-NSChapUser,   
    New-NSWitness,    Get-NSWitness,    Remove-NSWitness,    Test-NSWitness,   
    New-NSPool,    Get-NSPool,    Set-NSPool,    Remove-NSPool,   
    Merge-NSPool,    Invoke-NSPoolDeDupe,    Get-NSFibreChannelInitiatorAlias,    New-NSProtectionTemplate,   
    Get-NSProtectionTemplate,    Set-NSProtectionTemplate,    Remove-NSProtectionTemplate,    New-NSInitiatorGroup,   
    Get-NSInitiatorGroup,    Set-NSInitiatorGroup,    Remove-NSInitiatorGroup,    Resolve-NSInitiatorGroupMerge,   
    Test-NSInitiatorGroupLunAvailability,    New-NSSnapshot,    Get-NSSnapshot,    Set-NSSnapshot,   
    Remove-NSSnapshot,    New-NSSnapshotBulk,    New-NSVolume,    Get-NSVolume,   
    Set-NSVolume,    Remove-NSVolume,    Restore-NSVolume,    Move-NSVolume,   
    Move-NSVolumeBulk,    Stop-NSVolumeMove,    Set-NSVolumeBulkDeDupe,    Set-NSVolumeBulkOnline,   
    New-NSActiveDirectoryMembership,    Get-NSActiveDirectoryMembership,    Set-NSActiveDirectoryMembership,    Remove-NSActiveDirectoryMembership,   
    Test-NSActiveDirectoryMembership,    Test-NSActiveDirectoryMembershipUser,    Test-NSActiveDirectoryMembershipGroup,    Get-NSSubnet,   
    Get-NSSpaceDomain,    Get-NSGroup,    Set-NSGroup,    Reset-NSGroup,   
    Stop-NSGroup,    Test-NSGroupAlert,    Test-NSGroupSoftwareUpdate,    Start-NSGroupSoftwareUpdate,   
    Start-NSGroupSoftwareDownload,    Stop-NSGroupSoftwareDownload,    Resume-NSGroupSoftwareUpdate,    Get-NSGroupDiscoveredList,   
    Test-NSGroupMerge,    Merge-NSGroup,    Get-NSGroupgetEULA,    Test-NSGroupMigrate,   
    Move-NSGroup,    Get-NSGroupTimeZoneList,    New-NSReplicationPartner,    Get-NSReplicationPartner,   
    Set-NSReplicationPartner,    Remove-NSReplicationPartner,    Suspend-NSReplicationPartner,    Resume-NSReplicationPartner,   
    Test-NSReplicationPartner,    New-NSFolder,    Get-NSFolder,    Set-NSFolder,   
    Remove-NSFolder,    Invoke-NSFolderDeDupe,    New-NSNetworkConfig,    Get-NSNetworkConfig,   
    Set-NSNetworkConfig,    Remove-NSNetworkConfig,    Initialize-NSNetworkConfig,    Test-NSNetworkConfig,   
    Get-NSController,    Stop-NSController,    Reset-NSController,    New-NSProtectionSchedule,   
    Get-NSProtectionSchedule,    Set-NSProtectionSchedule,    Remove-NSProtectionSchedule,    New-NSMasterKey,   
    Get-NSMasterKey,    Set-NSMasterKey,    Remove-NSMasterKey,    Clear-NSMasterKeyInactive,   
    Get-NSEvent,    New-NSApplicationServer,    Get-NSApplicationServer,    Set-NSApplicationServer,   
    Remove-NSApplicationServer,    Get-NSFibreChannelPort,    Get-NSApplicationCategory,    Get-NSAuditLog,   
    New-NSInitiator,    Get-NSInitiator,    Remove-NSInitiator,    Get-NSVersion,   
    New-NSPerformancePolicy,    Get-NSPerformancePolicy,    Set-NSPerformancePolicy,    Remove-NSPerformancePolicy,   
    Get-NSJob,    Get-NSDisk,    Set-NSDisk,    Get-NSNetworkInterface,   
    Get-NSUserPolicy,    Set-NSUserPolicy,    Get-NSSoftwareVersion,    New-NSSnapshotCollection,   
    Get-NSSnapshotCollection,    Set-NSSnapshotCollection,    Remove-NSSnapshotCollection,    Get-NSFibreChannelConfig,   
    Update-NSFibreChannelConfig,    Update-NSFibreChannelConfig,    New-NSUser,    Get-NSUser,   
    Set-NSUser,    Remove-NSUser,    Unlock-NSUser,    Get-NSShelf,   
    Set-NSShelf,    Show-NSShelf,    Get-NSProtocolEndpoint,    Get-NSFibreChannelInterface,   
    Set-NSFibreChannelInterface,    Get-NSFibreChannelSession,    New-NSArray,    Get-NSArray,   
    Set-NSArray,    Remove-NSArray,    Invoke-NSArray,    Stop-NSArray,   
    Reset-NSArray,    Get-NSAlarm,    Set-NSAlarm,    Remove-NSAlarm,   
    Clear-NSAlarm,    Undo-NSAlarm,     Connect-AZNSVolume

