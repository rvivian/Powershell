######################################################
# Name: Update-LicenseAndGroupMembership.ps1         #
# Author: Rhyss Vivian                               #
# Date: March 26, 2019                               #
# Version: 1.0                                       #
######################################################

#Connect to MSOnline Servicing. Will prompt for admin credentials and MFA
Connect-MsolService

$E1License = New-Object System.Object
$E1License | Add-Member -Name Name -Value "E1"
$E1License | Add-Member -Name SkuID -Value "STANDARDPACK"

$E3License = New-Object System.Object
$E3License | Add-Member -Name Name -Value "E3"
$E3License | Add-Member -Name SkuID -Value "ENTERPRISEPACK"

$F1License = New-Object System.Object
$F1License | Add-Member -Name Name -Value "F1"
$F1License | Add-Member -Name SkuID -Value "DESKLESSPACK"

$Licenses = $E1License,$E3License,$F1License

ForEach ($License in $Licenses) {

  $LicenseName = $License.Name
  $LicenseSku = $License.SkuID

  #Select the UPNs for all users in the O365-E3-License group
  $LicenseGroupMembers = Get-ADGroupMember -Identity "O365-$LicenseName-License" | Get-ADUser | Select-Object -Property UserPrincipalName
  #Select the UPNs for all users with an E3 License
  $LicensedUsers = Get-MsolUser -MaxResults 10000 | Where-Object {($_.licenses).AccountSkuID -Match $LicenseSku} | Select-Object -Property UserPrincipalName
  
  #Compare the groups
  $UsersWithLicensesNotInGroup = Compare-Object -ReferenceObject $LicensedUsers.UserPrincipalName -DifferenceObject $LicenseGroupMembers.UserPrincipalName -PassThru | Where-Object { $_.SideIndicator -eq "<=" }
  $UsersInGroupWithNoLicense = Compare-Object -ReferenceObject $LicensedUsers.UserPrincipalName -DifferenceObject $LicenseGroupMembers.UserPrincipalName -PassThru | Where-Object { $_.SideIndicator -eq "=>" }
  
  #If the user has a license, but is not part of the group, add them
  ForEach($User in $UsersWithLicensesNotInGroup) {
      $ADUser = Get-ADUser -Identity $User.TrimEnd('@chugachgov.com')
      Write-Host "Adding" $ADUser.Name "to O365-$LicenseName-License group"
      Add-ADGroupMember -Identity "O365-$LicenseName-License" -Members $ADUser
    }
    Write-Host "Added" $UsersWithLicensesNotInGroup.Count "to O365-$LicenseName-License Group"
    
    #If the user is part of the group, but does not have a license, remove them
    ForEach($User in $UsersInGroupWithNoLicense) {
      $ADUser = Get-ADUser -Identity $User.TrimEnd('@chugachgov.com')
      Write-Host "Removing" $ADUser.Name "from O365-$LicenseName-License group"
      Remove-ADGroupMember -Identity "O365-$LicenseName-License" -Members $ADUser -Confirm:$False
    }
    Write-Host "Removed" $UsersInGroupWithNoLicense.Count "from O365-$LicenseName-License Group"
}
