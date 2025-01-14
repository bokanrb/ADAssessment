# Verificar se o módulo Microsoft.Graph e Az.KeyVault estão instalados
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module -Name Microsoft.Graph -Force -Scope CurrentUser
}
if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
    Install-Module -Name Az.KeyVault -Force -Scope CurrentUser
}

# Importar os módulos
Import-Module Microsoft.Graph
Import-Module Az.KeyVault

# Autenticar no Azure
Connect-AzAccount

# Nome do Key Vault
$keyVaultName = "AKVTeste"

# Buscar segredos do Key Vault
$clientId = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name "ClientId").SecretValueText
$tenantId = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name "TenantId").SecretValueText
$clientSecret = (Get-AzKeyVaultSecret -VaultName $keyVaultName -Name "ClientSecret").SecretValueText

# Autenticar usando token
$body = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

$response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
$token = $response.access_token

# Buscar grupos privilegiados usando Microsoft Graph API
$headers = @{
    Authorization = "Bearer $token"
}

$privilegedGroups = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $headers

# Filtrar e exibir os grupos privilegiados
$privilegedGroups.value | Where-Object { $_.displayName -match "Admin" } | ForEach-Object {
    Write-Output "Group: $($_.displayName)"
}
