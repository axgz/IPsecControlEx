#Requires -RunAsAdministrator

[CmdletBinding()]

param (
    [Parameter(Mandatory=$true,ParameterSetName='Update')]
    [switch]$Update,
    
    [Parameter(Mandatory=$true,ParameterSetName='Create')]
    [switch]$Create,

    [Parameter(Mandatory=$true,ParameterSetName='Delete')]
    [switch]$Delete,

    [Parameter(Mandatory=$true,ParameterSetName='Show')]
    [switch]$Show,

    [Parameter(Mandatory=$false)]
    [switch]$UseLocalPersistentStore
)

#region IPsec Rules (N.B. An empty array matches to ALL "*")
if ($Create -or $Update) {    
    $IPsecRules = @(
        @{
            Protect = $true
            DisplayName = "RDP (TCP 3389) to any target."
            UniqueId = "RDP Global"
            Protocol = "TCP"
            RemotePort = @(
                "3389"
            )
            RemoteAddress = @(
            )
        },
        @{
            Protect = $true
            DisplayName = "WinRM (TCP 5985, 5986) to any target."
            UniqueId = "WINRM Global"
            Protocol = "TCP"
            RemotePort = @(
                "5985",
                "5986"
            )
            RemoteAddress = @(
            )
        },
        @{
            Protect = $true
            DisplayName = "All (*) to the VPN-Pool subnet."
            UniqueId = "All VPN-Pool"
            Protocol = "Any"
            RemotePort = @(
            )
            RemoteAddress = @(
                "10.11.0.0/24"
            )
        },
        @{
            Protect = $true
            DisplayName = "All (*) to T0PAW-01."
            UniqueId = "All T0PAW-01"
            Protocol = "Any"
            RemotePort = @(
            )
            RemoteAddress = @(
                "10.16.0.20/32"
            )
        }
    )    
}
#endregion

###############################################################################
#### DO NOT CHANGE ANYTHING PAST THIS POINT
###############################################################################

function Load-Config {
    [CmdletBinding()]

    param (
        [Parameter(Position=0,Mandatory=$true)] 
        [string]$Path
    )

    Get-Content -Path $Path | ConvertFrom-Json
}

function Save-Config {

    [CmdletBinding()]

    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)] 
        $InputObject,
        [Parameter(Position=1,Mandatory=$true)] 
        [string]$Path
    )

    $InputObject | ConvertTo-Json | Out-File -FilePath $Path -Force
}

Write-Host -ForegroundColor Yellow "`nLoading application 'config.json' file."
$config = Load-Config -Path 'C:\Program Files\Tools\IPsecControlEx\config.json'

#region GPO & Root Cert
if (-not $UseLocalPersistentStore) {
    if ($config.AppSettings.ServerGpoId -eq '') {
        $gpo = Get-GPO -All | Out-GridView -OutputMode Single -Title "Select the 'Server' IPsec Policy GPO"
        $config.AppSettings.ServerGpoId = $gpo.Id.Guid
    }
    else {
        $gpo = Get-GPO -Id $config.AppSettings.ServerGpoId
    }
}

if ($Create) {
    if ($config.AppSettings.RootCertificateThumbprint -eq '') {
        $certificate = Get-ChildItem "Cert:\LocalMachine\Root" | Out-GridView -OutputMode Single -Title "Select the Root Certificate Authority for this IPsec channel"
        $config.AppSettings.RootCertificateThumbprint = $certificate.Thumbprint
    }
    else {
        $certificate = Get-Item ("Cert:\LocalMachine\Root\{0}" -f $config.AppSettings.RootCertificateThumbprint)
    }
}
#endregion

Write-Host -ForegroundColor Yellow "`nSaving application 'config.json' file."
$config | Save-Config -Path 'C:\Program Files\Tools\IPsecControlEx\config.json'

#region Configuration
if ($UseLocalPersistentStore) {
    $IPsecPolicyStore = "PersistentStore"
}
else {
    $IPsecPolicyStore = "LDAP://" + $gpo.Path
}
    
    if ($certificate.Subject -like '*,*') {
        $IPsecCertificatePath = $certificate.Subject -split ', '
        [array]::Reverse($IPsecCertificatePath)
        $IPsecCertificatePath = $IPsecCertificatePath -join ', '
    }
    else {
        $IPsecCertificatePath = $certificate.Subject
    }

    $IPsecKeyModule = "IKEv2"
    $IPsecKeyExchange = "dh19"
    $IPsecMaxSessions = 1
    $IPsecStrongCrlCheck = 0
    $IPSsecPerfectForwardSecrecy = $true    
    $IPsecMMEncryption = "aes256"
    $IPsecMMHash = "sha256"
    $IPsecQMEncapsulation = @("AH", "ESP")
    $IPsecQMEncryption = "aesgcm256"
    $IPsecQMHashAH = "aesgmac256"
    $IPsecQMHashESP = "aesgmac256"

#endregion

#region Pre-req firewall settings
if ($Create) {
    Get-NetFirewallSetting -PolicyStore $IPsecPolicyStore |
        Set-NetFirewallSetting -Exemptions Icmp

    Get-NetFirewallSetting -PolicyStore $IPsecPolicyStore |
        Set-NetFirewallSetting -CertValidationLevel $IPsecStrongCrlCheck

    Set-NetFirewallProfile -PolicyStore $IPsecPolicyStore `
        -Profile Domain, Public, Private `
        -Enabled True

    Set-NetFirewallProfile -PolicyStore $IPsecPolicyStore `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -AllowLocalIPsecRules True `
        -EnableStealthModeForIPsec True `
        -LogAllowed True `
        -LogBlocked True `
        -LogMaxSizeKilobytes 32767 `
        -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
}
#endregion

#region Create Auth & Crypto sets
if ($Create) {
    Write-Host -ForegroundColor Green ("+    Main Mode Crypto Set (Phase 1) IKE_SA_INIT")
    $mmProposal = New-NetIPsecMainModeCryptoProposal -Encryption $IPsecMMEncryption -Hash $IPsecMMHash -KeyExchange $IPsecKeyExchange
    $mmCryptoSet = New-NetIPsecMainModeCryptoSet -PolicyStore $IPsecPolicyStore `
        -DisplayName "Main Mode Crypto Set (Phase 1) IKE_SA_INIT" `
        -Proposal $mmProposal `
        -MaxSessions $IPsecMaxSessions `
        -ForceDiffieHellman $IPSsecPerfectForwardSecrecy

    Write-Host -ForegroundColor Green ("+    Quick Mode Cypto Set (Phase 2) CREATE_CHILD_SA")
    $qmProposal = New-NetIPsecQuickModeCryptoProposal -Encapsulation $IPsecQMEncapsulation -Encryption $IPsecQMEncryption -ESPHash $IPsecQMHashESP -AHHash $IPsecQMHashAH
    $qmCryptoSet = New-NetIPsecQuickModeCryptoSet -PolicyStore $IPsecPolicyStore `
        -DisplayName "Quick Mode Cypto Set (Phase 2) CREATE_CHILD_SA" `
        -Proposal $qmProposal `
        -PerfectForwardSecrecyGroup SameAsMainMode

    Write-Host -ForegroundColor Green ("+    Main Mode Auth Set (Phase 1) IKE_AUTH")
    $p1Proposal = New-NetIPsecAuthProposal -Machine -Cert -Authority $IPsecCertificatePath -AuthorityType Root
    $p1AuthSet = New-NetIPsecPhase1AuthSet -PolicyStore $IPsecPolicyStore `
        -DisplayName "Main Mode Auth Set (Phase 1) IKE_AUTH" `
        -Proposal $p1Proposal
}
#endregion

#region Select Auth & Crypto sets
if ($Update) {
    $qmCryptoSet = Get-NetIPsecQuickModeCryptoSet -PolicyStore $IPsecPolicyStore `
        -DisplayName "Quick Mode Cypto Set (Phase 2) CREATE_CHILD_SA"

    $p1AuthSet = Get-NetIPsecPhase1AuthSet -PolicyStore $IPsecPolicyStore `
        -DisplayName "Main Mode Auth Set (Phase 1) IKE_AUTH"
}
#endregion

#region Create IPsec Rules
if ($Create) {
    Write-Host -ForegroundColor Green ("+    Main Mode Rule")
    New-NetIPsecMainModeRule -PolicyStore $IPsecPolicyStore `
        -DisplayName "Main Mode Rule" `
        -MainModeCryptoSet $mmCryptoSet.Name `
        -Phase1AuthSet $p1AuthSet.Name
}

if ($Create -or $Update) {
    $existingIPsecRuleNames = Get-NetIPsecRule -PolicyStore $IPsecPolicyStore | 
        Select-Object -ExpandProperty IPsecRuleName

    foreach ($rule in $IPsecRules) {
        if ($rule.Protect) {
            if ($existingIPsecRuleNames -contains ("RQST {0}" -f $rule.UniqueId)) {
                Write-Host -ForegroundColor DarkYellow ("-    RQST {0}" -f $rule.UniqueId)
                Remove-NetIPsecRule -IPsecRuleName ("RQST {0}" -f $rule.UniqueId) -PolicyStore $IPsecPolicyStore
            }
            Write-Host -ForegroundColor Green ("+    RQST {0}" -f $rule.UniqueId)
            New-NetIPsecRule -PolicyStore $IPsecPolicyStore `
                -Enabled False `
                -InboundSecurity Request `
                -OutboundSecurity Request `
                -KeyModule $IPsecKeyModule `
                -QuickModeCryptoSet $qmCryptoSet.Name `
                -Phase1AuthSet $p1AuthSet.Name `
                -Protocol $rule.Protocol `
                -RemotePort $rule.RemotePort `
                -RemoteAddress $rule.RemoteAddress `
                -Name ("RQST {0}" -f $rule.UniqueId) `
                -DisplayName ("[     ] Request - {0}" -f $rule.DisplayName)

            if ($existingIPsecRuleNames -contains ("RQRE {0}" -f $rule.UniqueId)) {
                Write-Host -ForegroundColor DarkYellow ("-    RQRE {0}" -f $rule.UniqueId)
                Remove-NetIPsecRule -IPsecRuleName ("RQRE {0}" -f $rule.UniqueId) -PolicyStore $IPsecPolicyStore
            }
            Write-Host -ForegroundColor Green ("+    RQRE {0}" -f $rule.UniqueId)
            New-NetIPsecRule -PolicyStore $IPsecPolicyStore `
                -Enabled False `
                -InboundSecurity Require `
                -OutboundSecurity Require `
                -KeyModule $IPsecKeyModule `
                -QuickModeCryptoSet $qmCryptoSet.Name `
                -Phase1AuthSet $p1AuthSet.Name `
                -Protocol $rule.Protocol `
                -RemotePort $rule.RemotePort `
                -RemoteAddress $rule.RemoteAddress `
                -Name ("RQRE {0}" -f $rule.UniqueId) `
                -DisplayName ("[ !!! ] Require - {0}" -f $rule.DisplayName)
        }
        else {
            if ($existingIPsecRuleNames -contains ("BYPS {0}" -f $rule.UniqueId)) {
                Write-Host -ForegroundColor DarkYellow ("-    BYPS {0}" -f $rule.UniqueId)
                Remove-NetIPsecRule -IPsecRuleName ("BYPS {0}" -f $rule.UniqueId) -PolicyStore $IPsecPolicyStore
            }
            Write-Host -ForegroundColor Green ("+    BYPS {0}" -f $rule.UniqueId)
            New-NetIPsecRule -PolicyStore $IPsecPolicyStore `
                -Enabled True `
                -InboundSecurity None `
                -OutboundSecurity None `
                -Protocol $rule.Protocol `
                -RemotePort $rule.RemotePort `
                -RemoteAddress $rule.RemoteAddress `
                -Name ("BYPS {0}" -f $rule.UniqueId) `
                -DisplayName ("Bypass - {0}" -f $rule.DisplayName)
        }
    }      
}
#endregion

#region Check all
if ($Show) {
    Get-NetIPsecRule -PolicyStore $IPsecPolicyStore 

    Get-NetIPsecMainModeRule -PolicyStore $IPsecPolicyStore

    Get-NetIPsecQuickModeCryptoSet -PolicyStore $IPsecPolicyStore
    Get-NetIPsecMainModeCryptoSet -PolicyStore $IPsecPolicyStore
    Get-NetIPsecPhase2AuthSet -PolicyStore $IPsecPolicyStore
    Get-NetIPsecPhase1AuthSet -PolicyStore $IPsecPolicyStore
}
#endregion

#region Delete all
if ($Delete) {
    Get-NetIPsecRule -PolicyStore $IPsecPolicyStore | 
        ForEach-Object {
            Write-Host -ForegroundColor DarkYellow ("-    {0}" -f $_.IPsecRuleName)
            $_ | Remove-NetIPsecRule -PolicyStore $IPsecPolicyStore
        }

    Get-NetIPsecMainModeRule -PolicyStore $IPsecPolicyStore | 
        ForEach-Object {
            Write-Host -ForegroundColor DarkYellow ("-    {0}" -f $_.DisplayName)
            Remove-NetIPsecMainModeRule -PolicyStore $IPsecPolicyStore -Name $_.Name
        }

    Get-NetIPsecQuickModeCryptoSet -PolicyStore $IPsecPolicyStore| 
        ForEach-Object {
            Write-Host -ForegroundColor DarkYellow ("-    {0}" -f $_.DisplayName)
            Remove-NetIPsecQuickModeCryptoSet -PolicyStore $IPsecPolicyStore -Name $_.Name
        }
    
    Get-NetIPsecMainModeCryptoSet -PolicyStore $IPsecPolicyStore| 
        ForEach-Object {
            Write-Host -ForegroundColor DarkYellow ("-    {0}" -f $_.DisplayName)
            Remove-NetIPsecMainModeCryptoSet -PolicyStore $IPsecPolicyStore -Name $_.Name
        }        
    
    Get-NetIPsecPhase2AuthSet -PolicyStore $IPsecPolicyStore| 
        ForEach-Object {
            Write-Host -ForegroundColor DarkYellow ("-    {0}" -f $_.DisplayName)
            Remove-NetIPsecPhase2AuthSet -PolicyStore $IPsecPolicyStore -Name $_.Name
        }
    
    Get-NetIPsecPhase1AuthSet -PolicyStore $IPsecPolicyStore| 
        ForEach-Object {
            Write-Host -ForegroundColor DarkYellow ("-    {0}" -f $_.DisplayName)
            Remove-NetIPsecPhase1AuthSet -PolicyStore $IPsecPolicyStore -Name $_.Name
        }
}
#endregion
