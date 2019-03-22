$UserPath = "%UserProfile%\Desktop\outputfile.txt"
Get-process | Out-File $Userpath
