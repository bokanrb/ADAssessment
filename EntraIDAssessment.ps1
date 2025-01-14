# Verificar se o módulo Microsoft.Graph está instalado
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module -Name Microsoft.Graph -Force -Scope CurrentUser
}

# Importar o módulo Microsoft.Graph
Import-Module Microsoft.Graph

# Autenticar usando token
#$clientId = "ENTER HERE"
#$tenantId = "ENTER HERE"
#$clientSecret = "ENTER HERE"

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
