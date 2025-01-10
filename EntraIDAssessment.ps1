# Conectar ao EntraID
Connect-AzureAD

# Buscar grupos privilegiados
$privilegedGroups = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -match "Admin" }

# Exibir os grupos privilegiados
$privilegedGroups | ForEach-Object {
    Write-Output "Group: $($_.DisplayName)"
}