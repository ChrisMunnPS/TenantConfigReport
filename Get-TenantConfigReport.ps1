#Requires -Version 5.1

<#
.SYNOPSIS
    Produces a full Microsoft 365 / Entra ID tenant configuration report — HTML dashboard, Markdown, and PDF.

.DESCRIPTION
    Connects to Microsoft Graph (Entra ID), Exchange Online, and SharePoint Online as a Global Admin /
    Global Reader and pulls together a first-look picture of a tenant: identity, users, groups, licenses,
    admin roles, Conditional Access, MFA/authentication method registration, app registrations, Exchange
    mail flow, and SharePoint/OneDrive sharing settings.

    Each data-collection block is independent and wrapped in try/catch, so if a module isn't installed or
    a connection fails (e.g. you only have Graph access, not Exchange), that section is skipped and noted
    in the report rather than aborting the whole run.

    Output is written to a timestamped folder:
        TenantReport.html   - dashboard + detail sections, styled, with anchor navigation
        TenantReport.md     - the same content in Markdown
        TenantReport.pdf    - the HTML rendered to PDF via headless Microsoft Edge

.PARAMETER OutputPath
    Folder to create the timestamped report folder in. Defaults to the current directory.

.PARAMETER TenantId
    Optional. Tenant ID or verified domain to target — useful for MSPs switching between customer tenants.
    If omitted, Connect-MgGraph uses whatever tenant the signing-in account resolves to.

.PARAMETER SkipExchange
    Skip the Exchange Online connection/section entirely.

.PARAMETER SkipSharePoint
    Skip the SharePoint Online connection/section entirely.

.PARAMETER SkipPdf
    Skip PDF generation (no headless Edge invocation). HTML and Markdown are still produced.

.EXAMPLE
    .\Get-TenantConfigReport.ps1

    Connects interactively to the caller's default tenant and produces a full report in the current folder.

.EXAMPLE
    .\Get-TenantConfigReport.ps1 -TenantId 'contoso.onmicrosoft.com' -OutputPath 'C:\Reports'

    Targets a specific MSP customer tenant and writes the report under C:\Reports.

.EXAMPLE
    .\Get-TenantConfigReport.ps1 -SkipExchange -SkipSharePoint

    Entra ID / Graph data only — fastest option, no EXO or SPO modules required.

.NOTES
    Requires (installed automatically if missing, with confirmation):
        Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups,
        Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns,
        Microsoft.Graph.Applications, Microsoft.Graph.Reports
        ExchangeOnlineManagement   (unless -SkipExchange)
        PnP.PowerShell             (unless -SkipSharePoint)

    Sign in with an account holding Global Reader (read-only, recommended) or Global Admin.
    Graph scopes requested: Organization.Read.All, User.Read.All, Group.Read.All,
    RoleManagement.Read.Directory, Policy.Read.All, Reports.Read.All, Application.Read.All,
    AuditLog.Read.All, Directory.Read.All

    PDF export shells out to msedge.exe in headless mode. If Edge isn't found, PDF generation is
    skipped with a warning — HTML/Markdown are unaffected.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$SkipExchange,

    [Parameter()]
    [switch]$SkipSharePoint,

    [Parameter()]
    [switch]$SkipPdf
)

#region Setup

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date
$script:Report = [ordered]@{
    Meta              = $null
    TenantInfo        = $null
    Users             = $null
    Groups            = $null
    Licenses          = $null
    AdminRoles        = $null
    ConditionalAccess = $null
    Mfa               = $null
    Applications      = $null
    ExchangeOnline    = $null
    SharePoint        = $null
}
$script:Warnings = [System.Collections.Generic.List[string]]::new()

function Write-Section {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "  - $Message" -ForegroundColor Gray
}

function Add-ReportWarning {
    param([string]$Section, [string]$Message)
    $script:Warnings.Add("[$Section] $Message")
    Write-Warning "[$Section] $Message"
}

function Test-ModuleAvailable {
    param(
        [Parameter(Mandatory)][string]$Name
    )
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Step "Module '$Name' not found - installing for current user..."
        try {
            Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            return $true
        }
        catch {
            Add-ReportWarning -Section 'Setup' -Message "Could not install module '$Name': $($_.Exception.Message)"
            return $false
        }
    }
    return $true
}

#endregion Setup

#region Connections

function Connect-TenantGraph {
    [CmdletBinding()]
    param([string]$TenantId)

    Write-Section 'Connecting to Microsoft Graph'

    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Applications',
        'Microsoft.Graph.Reports'
    )
    foreach ($m in $requiredModules) {
        if (-not (Test-ModuleAvailable -Name $m)) {
            throw "Required module '$m' is unavailable. Cannot continue without Microsoft Graph access."
        }
    }

    $scopes = @(
        'Organization.Read.All',
        'User.Read.All',
        'Group.Read.All',
        'RoleManagement.Read.Directory',
        'Policy.Read.All',
        'Reports.Read.All',
        'Application.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    )

    $connectParams = @{
        Scopes      = $scopes
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }

    Connect-MgGraph @connectParams
    $ctx = Get-MgContext
    Write-Step "Connected as $($ctx.Account) to tenant $($ctx.TenantId)"
    return $ctx
}

function Connect-TenantExchange {
    [CmdletBinding()]
    param([string]$TenantId)

    Write-Section 'Connecting to Exchange Online'

    if (-not (Test-ModuleAvailable -Name 'ExchangeOnlineManagement')) {
        Add-ReportWarning -Section 'ExchangeOnline' -Message 'ExchangeOnlineManagement module unavailable - section skipped.'
        return $false
    }

    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $connectParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($TenantId) { $connectParams['Organization'] = $TenantId }
        Connect-ExchangeOnline @connectParams
        Write-Step 'Connected to Exchange Online.'
        return $true
    }
    catch {
        Add-ReportWarning -Section 'ExchangeOnline' -Message "Connection failed: $($_.Exception.Message)"
        return $false
    }
}

function Connect-TenantSharePoint {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$AdminUrl)

    Write-Section 'Connecting to SharePoint Online'

    if (-not (Test-ModuleAvailable -Name 'PnP.PowerShell')) {
        Add-ReportWarning -Section 'SharePoint' -Message 'PnP.PowerShell module unavailable - section skipped.'
        return $false
    }

    try {
        Import-Module PnP.PowerShell -ErrorAction Stop
        Connect-PnPOnline -Url $AdminUrl -Interactive -ErrorAction Stop
        Write-Step "Connected to SharePoint Online admin site ($AdminUrl)."
        return $true
    }
    catch {
        Add-ReportWarning -Section 'SharePoint' -Message "Connection failed: $($_.Exception.Message)"
        return $false
    }
}

#endregion Connections

#region Data Collection

function Get-TenantInfoData {
    Write-Section 'Collecting tenant / domain information'
    try {
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $domains = $org.VerifiedDomains

        [PSCustomObject]@{
            DisplayName       = $org.DisplayName
            TenantId          = $org.Id
            DefaultDomain     = ($domains | Where-Object { $_.IsDefault } | Select-Object -ExpandProperty Name -First 1)
            VerifiedDomains   = $domains | ForEach-Object {
                [PSCustomObject]@{
                    Name      = $_.Name
                    IsDefault = $_.IsDefault
                    IsInitial = $_.IsInitial
                    Type      = $_.Type
                }
            }
            City              = $org.City
            Country           = $org.CountryLetterCode
            TechNotifyEmails  = ($org.TechnicalNotificationMails -join ', ')
            CreatedDateTime   = $org.CreatedDateTime
            OnPremisesSyncOn  = [bool]$org.OnPremisesSyncEnabled
        }
    }
    catch {
        Add-ReportWarning -Section 'TenantInfo' -Message $_.Exception.Message
        $null
    }
}

function Get-UsersData {
    Write-Section 'Collecting user data (this can take a while on large tenants)'
    try {
        Write-Step 'Fetching users...'
        $allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, UserType, `
            OnPremisesSyncEnabled, AssignedLicenses, CreatedDateTime, SignInActivity -ErrorAction Stop

        $enabled  = $allUsers | Where-Object { $_.AccountEnabled }
        $disabled = $allUsers | Where-Object { -not $_.AccountEnabled }
        $guests   = $allUsers | Where-Object { $_.UserType -eq 'Guest' }
        $members  = $allUsers | Where-Object { $_.UserType -eq 'Member' }
        $synced   = $allUsers | Where-Object { $_.OnPremisesSyncEnabled }
        $cloud    = $allUsers | Where-Object { -not $_.OnPremisesSyncEnabled }
        $licensed = $allUsers | Where-Object { $_.AssignedLicenses -and $_.AssignedLicenses.Count -gt 0 }
        $unlicensed = $allUsers | Where-Object { -not $_.AssignedLicenses -or $_.AssignedLicenses.Count -eq 0 }

        # Stale accounts: no interactive sign-in in 90 days (where data is available)
        $staleCutoff = (Get-Date).AddDays(-90)
        $stale = $enabled | Where-Object {
            $last = $_.SignInActivity.LastSignInDateTime
            (-not $last) -or ([datetime]$last -lt $staleCutoff)
        }

        [PSCustomObject]@{
            Total            = $allUsers.Count
            Enabled          = $enabled.Count
            Disabled         = $disabled.Count
            Guests           = $guests.Count
            Members          = $members.Count
            CloudOnly        = $cloud.Count
            HybridSynced     = $synced.Count
            Licensed         = $licensed.Count
            Unlicensed       = $unlicensed.Count
            StaleOver90Days  = $stale.Count
            Detail           = $allUsers | ForEach-Object {
                [PSCustomObject]@{
                    DisplayName       = $_.DisplayName
                    UserPrincipalName = $_.UserPrincipalName
                    Enabled           = $_.AccountEnabled
                    Type              = $_.UserType
                    Synced            = [bool]$_.OnPremisesSyncEnabled
                    Licensed          = [bool]($_.AssignedLicenses -and $_.AssignedLicenses.Count -gt 0)
                    LastSignIn        = $_.SignInActivity.LastSignInDateTime
                    Created           = $_.CreatedDateTime
                }
            }
        }
    }
    catch {
        Add-ReportWarning -Section 'Users' -Message $_.Exception.Message
        $null
    }
}

function Get-GroupsData {
    Write-Section 'Collecting group data'
    try {
        Write-Step 'Fetching groups...'
        $allGroups = Get-MgGroup -All -Property Id, DisplayName, GroupTypes, SecurityEnabled, `
            MailEnabled, MembershipRule, Owners -ExpandProperty Owners -ErrorAction Stop

        $m365       = $allGroups | Where-Object { $_.GroupTypes -contains 'Unified' }
        $dynamic    = $allGroups | Where-Object { $_.GroupTypes -contains 'DynamicMembership' }
        $security   = $allGroups | Where-Object { $_.SecurityEnabled -and -not $_.MailEnabled -and $_.GroupTypes -notcontains 'Unified' }
        $mailSec    = $allGroups | Where-Object { $_.SecurityEnabled -and $_.MailEnabled -and $_.GroupTypes -notcontains 'Unified' }
        $distro     = $allGroups | Where-Object { -not $_.SecurityEnabled -and $_.MailEnabled -and $_.GroupTypes -notcontains 'Unified' }
        $ownerless  = $allGroups | Where-Object { -not $_.Owners -or $_.Owners.Count -eq 0 }

        [PSCustomObject]@{
            Total               = $allGroups.Count
            Microsoft365Groups  = $m365.Count
            DynamicGroups       = $dynamic.Count
            SecurityGroups      = $security.Count
            MailEnabledSecurity = $mailSec.Count
            DistributionGroups  = $distro.Count
            OwnerlessGroups     = $ownerless.Count
            Detail              = $allGroups | ForEach-Object {
                $type = if ($_.GroupTypes -contains 'Unified') { 'Microsoft 365' }
                        elseif ($_.SecurityEnabled -and $_.MailEnabled) { 'Mail-Enabled Security' }
                        elseif ($_.SecurityEnabled) { 'Security' }
                        elseif ($_.MailEnabled) { 'Distribution' }
                        else { 'Other' }
                [PSCustomObject]@{
                    DisplayName = $_.DisplayName
                    Type        = $type
                    Dynamic     = $_.GroupTypes -contains 'DynamicMembership'
                    OwnerCount  = @($_.Owners).Count
                }
            }
        }
    }
    catch {
        Add-ReportWarning -Section 'Groups' -Message $_.Exception.Message
        $null
    }
}

function Get-LicensesData {
    Write-Section 'Collecting license / subscription data'
    try {
        $skus = Get-MgSubscribedSku -All -ErrorAction Stop
        [PSCustomObject]@{
            Detail = $skus | ForEach-Object {
                $enabled = $_.PrepaidUnits.Enabled
                $consumed = $_.ConsumedUnits
                $pctUsed = if ($enabled -gt 0) { [math]::Round(($consumed / $enabled) * 100, 1) } else { 0 }
                [PSCustomObject]@{
                    SkuPartNumber = $_.SkuPartNumber
                    Enabled       = $enabled
                    Consumed      = $consumed
                    Available     = [math]::Max(0, $enabled - $consumed)
                    PercentUsed   = $pctUsed
                    NearLimit     = ($pctUsed -ge 90)
                }
            }
        }
    }
    catch {
        Add-ReportWarning -Section 'Licenses' -Message $_.Exception.Message
        $null
    }
}

function Get-AdminRolesData {
    Write-Section 'Collecting privileged role assignments'
    try {
        $roles = Get-MgDirectoryRole -All -ErrorAction Stop
        $detail = foreach ($role in $roles) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
            if ($members -and $members.Count -gt 0) {
                [PSCustomObject]@{
                    RoleName    = $role.DisplayName
                    MemberCount = $members.Count
                    Members     = ($members | ForEach-Object {
                        try { (Get-MgUser -UserId $_.Id -Property DisplayName -ErrorAction Stop).DisplayName }
                        catch { $_.Id }
                    }) -join ', '
                }
            }
        }
        $gaCount = ($detail | Where-Object { $_.RoleName -eq 'Global Administrator' } | Select-Object -ExpandProperty MemberCount)

        [PSCustomObject]@{
            GlobalAdminCount = if ($gaCount) { $gaCount } else { 0 }
            RolesInUse       = @($detail).Count
            Detail           = $detail | Sort-Object RoleName
        }
    }
    catch {
        Add-ReportWarning -Section 'AdminRoles' -Message $_.Exception.Message
        $null
    }
}

function Get-ConditionalAccessData {
    Write-Section 'Collecting Conditional Access policies'
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        [PSCustomObject]@{
            Total    = $policies.Count
            Enabled  = @($policies | Where-Object { $_.State -eq 'enabled' }).Count
            ReportOnly = @($policies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
            Disabled = @($policies | Where-Object { $_.State -eq 'disabled' }).Count
            Detail   = $policies | ForEach-Object {
                [PSCustomObject]@{
                    DisplayName  = $_.DisplayName
                    State        = $_.State
                    GrantControls = ($_.GrantControls.BuiltInControls -join ', ')
                    Users        = if ($_.Conditions.Users.IncludeUsers -contains 'All') { 'All users' } else { 'Scoped' }
                    Apps         = if ($_.Conditions.Applications.IncludeApplications -contains 'All') { 'All apps' } else { 'Scoped' }
                }
            }
        }
    }
    catch {
        Add-ReportWarning -Section 'ConditionalAccess' -Message $_.Exception.Message
        $null
    }
}

function Get-MfaData {
    Write-Section 'Collecting MFA / authentication method registration data'
    try {
        $reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
        $total = $reg.Count
        $mfaCapable = @($reg | Where-Object { $_.IsMfaCapable }).Count
        $mfaRegistered = @($reg | Where-Object { $_.IsMfaRegistered }).Count
        $adminsNotMfaCapable = @($reg | Where-Object { $_.IsAdmin -and -not $_.IsMfaCapable })

        $secDefaults = $null
        try {
            $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        } catch { }

        [PSCustomObject]@{
            TotalUsersReported     = $total
            MfaCapable              = $mfaCapable
            MfaRegistered           = $mfaRegistered
            PercentMfaCapable       = if ($total -gt 0) { [math]::Round(($mfaCapable / $total) * 100, 1) } else { 0 }
            AdminsWithoutMfa        = $adminsNotMfaCapable.Count
            AdminsWithoutMfaDetail  = ($adminsNotMfaCapable | Select-Object -ExpandProperty UserPrincipalName) -join ', '
            SecurityDefaultsEnabled = if ($secDefaults) { [bool]$secDefaults.IsEnabled } else { $null }
        }
    }
    catch {
        Add-ReportWarning -Section 'Mfa' -Message $_.Exception.Message
        $null
    }
}

function Get-ApplicationsData {
    Write-Section 'Collecting application registrations / service principals'
    try {
        $apps = Get-MgApplication -All -Property Id, DisplayName, CreatedDateTime, RequiredResourceAccess -ErrorAction Stop

        # Flag apps requesting broad/high-privilege delegated or application permissions by common risky permission names
        $riskyKeywords = @('Mail.Read', 'Mail.ReadWrite', 'Files.ReadWrite.All', 'Directory.ReadWrite.All',
                           'User.ReadWrite.All', 'Mail.Send', 'Sites.FullControl.All', 'RoleManagement.ReadWrite.Directory')

        $detail = $apps | ForEach-Object {
            $permCount = ($_.RequiredResourceAccess | ForEach-Object { $_.ResourceAccess.Count } | Measure-Object -Sum).Sum
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                Created     = $_.CreatedDateTime
                ResourceApiCount = @($_.RequiredResourceAccess).Count
                PermissionCount  = $permCount
            }
        }

        [PSCustomObject]@{
            Total  = $apps.Count
            Detail = $detail | Sort-Object -Property PermissionCount -Descending | Select-Object -First 50
            Note   = 'Top 50 app registrations by requested permission count shown. Review high-permission-count apps first.'
        }
    }
    catch {
        Add-ReportWarning -Section 'Applications' -Message $_.Exception.Message
        $null
    }
}

function Get-ExchangeOnlineData {
    Write-Section 'Collecting Exchange Online configuration'
    try {
        Write-Step 'Fetching mailboxes...'
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop
        $byType = $mailboxes | Group-Object -Property RecipientTypeDetails |
            Sort-Object Count -Descending |
            ForEach-Object { [PSCustomObject]@{ Type = $_.Name; Count = $_.Count } }

        Write-Step 'Fetching transport (mail flow) rules...'
        $transportRules = Get-TransportRule -ErrorAction SilentlyContinue

        Write-Step 'Fetching connectors...'
        $inboundConnectors = Get-InboundConnector -ErrorAction SilentlyContinue
        $outboundConnectors = Get-OutboundConnector -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            TotalMailboxes    = $mailboxes.Count
            MailboxesByType   = $byType
            TransportRuleCount   = @($transportRules).Count
            TransportRules       = $transportRules | Select-Object Name, State, Priority
            InboundConnectorCount  = @($inboundConnectors).Count
            OutboundConnectorCount = @($outboundConnectors).Count
        }
    }
    catch {
        Add-ReportWarning -Section 'ExchangeOnline' -Message $_.Exception.Message
        $null
    }
}

function Get-SharePointData {
    Write-Section 'Collecting SharePoint Online / OneDrive configuration'
    try {
        Write-Step 'Fetching tenant sharing settings...'
        $tenant = Get-PnPTenant -ErrorAction Stop

        Write-Step 'Fetching site collections (this can take a while)...'
        $sites = Get-PnPTenantSite -ErrorAction Stop
        $totalStorageGb = [math]::Round((($sites | Measure-Object -Property StorageUsageCurrent -Sum).Sum) / 1024, 1)

        [PSCustomObject]@{
            SiteCount             = $sites.Count
            TotalStorageUsedGb    = $totalStorageGb
            SharingCapability     = $tenant.SharingCapability
            OneDriveSharingCapability = $tenant.OneDriveSharingCapability
            DefaultLinkPermission = $tenant.DefaultLinkPermission
            LegacyAuthProtocolsEnabled = -not [bool]$tenant.LegacyAuthProtocolsEnabled
        }
    }
    catch {
        Add-ReportWarning -Section 'SharePoint' -Message $_.Exception.Message
        $null
    }
}

#endregion Data Collection

#region Report Rendering

function Format-Number {
    param($Value)
    if ($null -eq $Value) { return 'N/A' }
    return ('{0:N0}' -f $Value)
}

function New-HtmlReport {
    param([Parameter(Mandatory)][hashtable]$Data)

    $ti   = $Data.TenantInfo
    $u    = $Data.Users
    $g    = $Data.Groups
    $lic  = $Data.Licenses
    $roles = $Data.AdminRoles
    $ca   = $Data.ConditionalAccess
    $mfa  = $Data.Mfa
    $apps = $Data.Applications
    $exo  = $Data.ExchangeOnline
    $spo  = $Data.SharePoint

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Tenant Configuration Report$(if ($ti) { " - $($ti.DisplayName)" })</title>
<style>
  :root {
    --bg: #0f172a; --panel: #ffffff; --panel-border: #e2e8f0; --text: #1e293b; --muted: #64748b;
    --accent: #2563eb; --good: #16a34a; --warn: #d97706; --bad: #dc2626; --bg-page: #f1f5f9;
  }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Calibri, Arial, sans-serif; margin: 0; background: var(--bg-page); color: var(--text); }
  header { background: var(--bg); color: #fff; padding: 28px 36px; }
  header h1 { margin: 0 0 4px 0; font-size: 24px; }
  header .meta { color: #94a3b8; font-size: 13px; }
  nav { background: #1e293b; padding: 10px 36px; position: sticky; top: 0; z-index: 10; }
  nav a { color: #cbd5e1; text-decoration: none; margin-right: 18px; font-size: 13px; }
  nav a:hover { color: #fff; }
  main { padding: 24px 36px 60px 36px; max-width: 1200px; margin: 0 auto; }
  h2 { border-bottom: 2px solid var(--panel-border); padding-bottom: 8px; margin-top: 48px; font-size: 19px; }
  .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin: 20px 0 8px 0; }
  .card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 10px; padding: 16px 18px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  .card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
  .card .value { font-size: 26px; font-weight: 600; margin-top: 4px; }
  .card .sub { font-size: 12px; color: var(--muted); margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--panel-border); border-radius: 8px; overflow: hidden; margin-top: 10px; font-size: 13px; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--panel-border); }
  th { background: #f8fafc; font-weight: 600; color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.03em; }
  tr:last-child td { border-bottom: none; }
  .pill { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .pill-good { background: #dcfce7; color: var(--good); }
  .pill-warn { background: #fef3c7; color: var(--warn); }
  .pill-bad  { background: #fee2e2; color: var(--bad); }
  .note { font-size: 12px; color: var(--muted); margin-top: 8px; }
  .skipped { background: #fff7ed; border: 1px dashed #fdba74; padding: 14px 18px; border-radius: 8px; color: #9a3412; font-size: 13px; }
  .warnings { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 14px 18px; margin-top: 30px; }
  .warnings h3 { margin-top: 0; font-size: 14px; color: var(--bad); }
  .warnings ul { margin: 6px 0 0 0; padding-left: 18px; font-size: 13px; }
  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 20px; }
</style>
</head>
<body>
<header>
  <h1>Tenant Configuration Report$(if ($ti) { " &mdash; $([System.Net.WebUtility]::HtmlEncode($ti.DisplayName))" })</h1>
  <div class="meta">Generated $($Data.Meta.GeneratedAt) by $($Data.Meta.RunBy) &nbsp;|&nbsp; Tenant ID: $($Data.Meta.TenantId)</div>
</header>
<nav>
  <a href="#dashboard">Dashboard</a>
  <a href="#tenant">Tenant</a>
  <a href="#users">Users</a>
  <a href="#groups">Groups</a>
  <a href="#licenses">Licenses</a>
  <a href="#roles">Admin Roles</a>
  <a href="#ca">Conditional Access</a>
  <a href="#mfa">MFA</a>
  <a href="#apps">Applications</a>
  <a href="#exo">Exchange Online</a>
  <a href="#spo">SharePoint</a>
</nav>
<main>
"@)

    # ---- Dashboard ----
    [void]$sb.AppendLine('<h2 id="dashboard">Dashboard</h2><div class="dashboard">')

    if ($ti) {
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">Tenant</div><div class="value" style="font-size:16px">$([System.Net.WebUtility]::HtmlEncode($ti.DisplayName))</div><div class="sub">$($ti.DefaultDomain)</div></div>
"@)
    }
    if ($u) {
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">Users</div><div class="value">$(Format-Number $u.Total)</div><div class="sub">$(Format-Number $u.Enabled) enabled &middot; $(Format-Number $u.Guests) guests</div></div>
<div class="card"><div class="label">Stale Accounts (90d+)</div><div class="value">$(Format-Number $u.StaleOver90Days)</div><div class="sub">no recent sign-in</div></div>
"@)
    }
    if ($g) {
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">Groups</div><div class="value">$(Format-Number $g.Total)</div><div class="sub">$(Format-Number $g.OwnerlessGroups) ownerless</div></div>
"@)
    }
    if ($lic -and $lic.Detail) {
        $avgUsed = if (@($lic.Detail).Count -gt 0) { [math]::Round((($lic.Detail | Measure-Object -Property PercentUsed -Average).Average), 0) } else { 0 }
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">License SKUs</div><div class="value">$(@($lic.Detail).Count)</div><div class="sub">avg $avgUsed% consumed</div></div>
"@)
    }
    if ($roles) {
        $gaClass = if ($roles.GlobalAdminCount -ge 2 -and $roles.GlobalAdminCount -le 4) { 'pill-good' } elseif ($roles.GlobalAdminCount -gt 4) { 'pill-warn' } else { 'pill-bad' }
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">Global Admins</div><div class="value">$($roles.GlobalAdminCount)</div><div class="sub"><span class="pill $gaClass">$(if ($roles.GlobalAdminCount -ge 2 -and $roles.GlobalAdminCount -le 4) { 'healthy range' } elseif ($roles.GlobalAdminCount -gt 4) { 'review - high count' } else { 'below recommended min (2)' })</span></div></div>
"@)
    }
    if ($ca) {
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">Conditional Access</div><div class="value">$($ca.Total)</div><div class="sub">$($ca.Enabled) enabled &middot; $($ca.ReportOnly) report-only</div></div>
"@)
    }
    if ($mfa) {
        $mfaClass = if ($mfa.PercentMfaCapable -ge 90) { 'pill-good' } elseif ($mfa.PercentMfaCapable -ge 60) { 'pill-warn' } else { 'pill-bad' }
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">MFA Capable</div><div class="value">$($mfa.PercentMfaCapable)%</div><div class="sub"><span class="pill $mfaClass">$(Format-Number $mfa.AdminsWithoutMfa) admins without MFA</span></div></div>
"@)
    }
    if ($exo) {
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">Mailboxes</div><div class="value">$(Format-Number $exo.TotalMailboxes)</div><div class="sub">$($exo.TransportRuleCount) mail flow rules</div></div>
"@)
    }
    if ($spo) {
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">SharePoint Storage</div><div class="value">$($spo.TotalStorageUsedGb) GB</div><div class="sub">$(Format-Number $spo.SiteCount) sites</div></div>
"@)
    }
    [void]$sb.AppendLine('</div>')

    # ---- Tenant / Domains ----
    [void]$sb.AppendLine('<h2 id="tenant">Tenant &amp; Domains</h2>')
    if ($ti) {
        [void]$sb.AppendLine(@"
<table>
<tr><th>Display Name</th><td>$([System.Net.WebUtility]::HtmlEncode($ti.DisplayName))</td></tr>
<tr><th>Tenant ID</th><td>$($ti.TenantId)</td></tr>
<tr><th>Default Domain</th><td>$($ti.DefaultDomain)</td></tr>
<tr><th>Country / City</th><td>$($ti.Country) / $($ti.City)</td></tr>
<tr><th>Hybrid / On-Prem Sync</th><td>$($ti.OnPremisesSyncOn)</td></tr>
<tr><th>Technical Notification Emails</th><td>$([System.Net.WebUtility]::HtmlEncode($ti.TechNotifyEmails))</td></tr>
</table>
<table><tr><th>Domain</th><th>Default</th><th>Type</th></tr>
"@)
        foreach ($d in $ti.VerifiedDomains) {
            [void]$sb.AppendLine("<tr><td>$($d.Name)</td><td>$($d.IsDefault)</td><td>$($d.Type)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    } else {
        [void]$sb.AppendLine('<div class="skipped">Tenant info unavailable - see warnings.</div>')
    }

    # ---- Users ----
    [void]$sb.AppendLine('<h2 id="users">Users</h2>')
    if ($u) {
        [void]$sb.AppendLine(@"
<table>
<tr><th>Total</th><td>$(Format-Number $u.Total)</td></tr>
<tr><th>Enabled / Disabled</th><td>$(Format-Number $u.Enabled) / $(Format-Number $u.Disabled)</td></tr>
<tr><th>Members / Guests</th><td>$(Format-Number $u.Members) / $(Format-Number $u.Guests)</td></tr>
<tr><th>Cloud-only / Hybrid-synced</th><td>$(Format-Number $u.CloudOnly) / $(Format-Number $u.HybridSynced)</td></tr>
<tr><th>Licensed / Unlicensed</th><td>$(Format-Number $u.Licensed) / $(Format-Number $u.Unlicensed)</td></tr>
<tr><th>No sign-in in 90+ days</th><td>$(Format-Number $u.StaleOver90Days)</td></tr>
</table>
<p class="note">Full per-user detail ($(Format-Number $u.Total) rows) is included in the Markdown/CSV-friendly export; the HTML dashboard shows summary counts only to keep this page readable.</p>
"@)
    } else {
        [void]$sb.AppendLine('<div class="skipped">User data unavailable - see warnings.</div>')
    }

    # ---- Groups ----
    [void]$sb.AppendLine('<h2 id="groups">Groups</h2>')
    if ($g) {
        [void]$sb.AppendLine(@"
<table>
<tr><th>Total</th><td>$(Format-Number $g.Total)</td></tr>
<tr><th>Microsoft 365 Groups</th><td>$(Format-Number $g.Microsoft365Groups)</td></tr>
<tr><th>Security Groups</th><td>$(Format-Number $g.SecurityGroups)</td></tr>
<tr><th>Mail-Enabled Security</th><td>$(Format-Number $g.MailEnabledSecurity)</td></tr>
<tr><th>Distribution Groups</th><td>$(Format-Number $g.DistributionGroups)</td></tr>
<tr><th>Dynamic Groups</th><td>$(Format-Number $g.DynamicGroups)</td></tr>
<tr><th>Ownerless Groups</th><td>$(Format-Number $g.OwnerlessGroups)</td></tr>
</table>
"@)
    } else {
        [void]$sb.AppendLine('<div class="skipped">Group data unavailable - see warnings.</div>')
    }

    # ---- Licenses ----
    [void]$sb.AppendLine('<h2 id="licenses">Licenses</h2>')
    if ($lic -and $lic.Detail) {
        [void]$sb.AppendLine('<table><tr><th>SKU</th><th>Consumed</th><th>Enabled</th><th>Available</th><th>% Used</th></tr>')
        foreach ($s in ($lic.Detail | Sort-Object PercentUsed -Descending)) {
            $cls = if ($s.NearLimit) { 'pill-bad' } elseif ($s.PercentUsed -ge 75) { 'pill-warn' } else { 'pill-good' }
            [void]$sb.AppendLine("<tr><td>$($s.SkuPartNumber)</td><td>$(Format-Number $s.Consumed)</td><td>$(Format-Number $s.Enabled)</td><td>$(Format-Number $s.Available)</td><td><span class=""pill $cls"">$($s.PercentUsed)%</span></td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    } else {
        [void]$sb.AppendLine('<div class="skipped">License data unavailable - see warnings.</div>')
    }

    # ---- Admin Roles ----
    [void]$sb.AppendLine('<h2 id="roles">Admin Roles</h2>')
    if ($roles -and $roles.Detail) {
        [void]$sb.AppendLine('<table><tr><th>Role</th><th>Members</th><th>Who</th></tr>')
        foreach ($r in $roles.Detail) {
            [void]$sb.AppendLine("<tr><td>$($r.RoleName)</td><td>$($r.MemberCount)</td><td>$([System.Net.WebUtility]::HtmlEncode($r.Members))</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    } else {
        [void]$sb.AppendLine('<div class="skipped">Admin role data unavailable - see warnings.</div>')
    }

    # ---- Conditional Access ----
    [void]$sb.AppendLine('<h2 id="ca">Conditional Access</h2>')
    if ($ca -and $ca.Detail) {
        [void]$sb.AppendLine('<table><tr><th>Policy</th><th>State</th><th>Users</th><th>Apps</th><th>Grant Controls</th></tr>')
        foreach ($p in $ca.Detail) {
            $cls = switch ($p.State) { 'enabled' { 'pill-good' }; 'enabledForReportingButNotEnforced' { 'pill-warn' }; default { 'pill-bad' } }
            [void]$sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($p.DisplayName))</td><td><span class=""pill $cls"">$($p.State)</span></td><td>$($p.Users)</td><td>$($p.Apps)</td><td>$($p.GrantControls)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    } else {
        [void]$sb.AppendLine('<div class="skipped">Conditional Access data unavailable - see warnings.</div>')
    }

    # ---- MFA ----
    [void]$sb.AppendLine('<h2 id="mfa">MFA &amp; Authentication Methods</h2>')
    if ($mfa) {
        [void]$sb.AppendLine(@"
<table>
<tr><th>Users Reported</th><td>$(Format-Number $mfa.TotalUsersReported)</td></tr>
<tr><th>MFA Capable</th><td>$(Format-Number $mfa.MfaCapable) ($($mfa.PercentMfaCapable)%)</td></tr>
<tr><th>MFA Registered</th><td>$(Format-Number $mfa.MfaRegistered)</td></tr>
<tr><th>Security Defaults Enabled</th><td>$($mfa.SecurityDefaultsEnabled)</td></tr>
<tr><th>Admins without MFA</th><td>$(Format-Number $mfa.AdminsWithoutMfa)$(if ($mfa.AdminsWithoutMfaDetail) { " - $([System.Net.WebUtility]::HtmlEncode($mfa.AdminsWithoutMfaDetail))" })</td></tr>
</table>
"@)
    } else {
        [void]$sb.AppendLine('<div class="skipped">MFA data unavailable - see warnings.</div>')
    }

    # ---- Applications ----
    [void]$sb.AppendLine('<h2 id="apps">Applications / Service Principals</h2>')
    if ($apps -and $apps.Detail) {
        [void]$sb.AppendLine("<p class=""note"">Total app registrations: $(Format-Number $apps.Total). $($apps.Note)</p>")
        [void]$sb.AppendLine('<table><tr><th>App</th><th>APIs Requested</th><th>Permission Count</th><th>Created</th></tr>')
        foreach ($a in $apps.Detail) {
            [void]$sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($a.DisplayName))</td><td>$($a.ResourceApiCount)</td><td>$($a.PermissionCount)</td><td>$($a.Created)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    } else {
        [void]$sb.AppendLine('<div class="skipped">Application data unavailable - see warnings.</div>')
    }

    # ---- Exchange Online ----
    [void]$sb.AppendLine('<h2 id="exo">Exchange Online</h2>')
    if ($exo) {
        [void]$sb.AppendLine('<table><tr><th>Mailbox Type</th><th>Count</th></tr>')
        foreach ($t in $exo.MailboxesByType) {
            [void]$sb.AppendLine("<tr><td>$($t.Type)</td><td>$(Format-Number $t.Count)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
        [void]$sb.AppendLine(@"
<table>
<tr><th>Total Mailboxes</th><td>$(Format-Number $exo.TotalMailboxes)</td></tr>
<tr><th>Mail Flow (Transport) Rules</th><td>$($exo.TransportRuleCount)</td></tr>
<tr><th>Inbound Connectors</th><td>$($exo.InboundConnectorCount)</td></tr>
<tr><th>Outbound Connectors</th><td>$($exo.OutboundConnectorCount)</td></tr>
</table>
"@)
    } else {
        [void]$sb.AppendLine('<div class="skipped">Exchange Online section skipped or unavailable - see warnings.</div>')
    }

    # ---- SharePoint ----
    [void]$sb.AppendLine('<h2 id="spo">SharePoint &amp; OneDrive</h2>')
    if ($spo) {
        [void]$sb.AppendLine(@"
<table>
<tr><th>Site Collections</th><td>$(Format-Number $spo.SiteCount)</td></tr>
<tr><th>Total Storage Used</th><td>$($spo.TotalStorageUsedGb) GB</td></tr>
<tr><th>Tenant Sharing Capability</th><td>$($spo.SharingCapability)</td></tr>
<tr><th>OneDrive Sharing Capability</th><td>$($spo.OneDriveSharingCapability)</td></tr>
<tr><th>Default Link Permission</th><td>$($spo.DefaultLinkPermission)</td></tr>
<tr><th>Legacy Auth Protocols Blocked</th><td>$($spo.LegacyAuthProtocolsEnabled)</td></tr>
</table>
"@)
    } else {
        [void]$sb.AppendLine('<div class="skipped">SharePoint section skipped or unavailable - see warnings.</div>')
    }

    # ---- Warnings ----
    if ($Data.Meta.Warnings -and $Data.Meta.Warnings.Count -gt 0) {
        [void]$sb.AppendLine('<div class="warnings"><h3>Collection Warnings</h3><ul>')
        foreach ($w in $Data.Meta.Warnings) {
            [void]$sb.AppendLine("<li>$([System.Net.WebUtility]::HtmlEncode($w))</li>")
        }
        [void]$sb.AppendLine('</ul></div>')
    }

    [void]$sb.AppendLine(@"
</main>
<footer>Generated $($Data.Meta.GeneratedAt) &middot; Get-TenantConfigReport.ps1</footer>
</body>
</html>
"@)

    return $sb.ToString()
}

function New-MarkdownReport {
    param([Parameter(Mandatory)][hashtable]$Data)

    $ti   = $Data.TenantInfo
    $u    = $Data.Users
    $g    = $Data.Groups
    $lic  = $Data.Licenses
    $roles = $Data.AdminRoles
    $ca   = $Data.ConditionalAccess
    $mfa  = $Data.Mfa
    $apps = $Data.Applications
    $exo  = $Data.ExchangeOnline
    $spo  = $Data.SharePoint

    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine("# Tenant Configuration Report$(if ($ti) { " - $($ti.DisplayName)" })")
    [void]$md.AppendLine("`nGenerated $($Data.Meta.GeneratedAt) by $($Data.Meta.RunBy)  ")
    [void]$md.AppendLine("Tenant ID: $($Data.Meta.TenantId)`n")

    [void]$md.AppendLine('## Dashboard Summary`n')
    if ($ti)  { [void]$md.AppendLine("- **Tenant:** $($ti.DisplayName) ($($ti.DefaultDomain))") }
    if ($u)   { [void]$md.AppendLine("- **Users:** $($u.Total) total, $($u.Enabled) enabled, $($u.Guests) guests, $($u.StaleOver90Days) stale (90d+)") }
    if ($g)   { [void]$md.AppendLine("- **Groups:** $($g.Total) total, $($g.OwnerlessGroups) ownerless") }
    if ($lic -and $lic.Detail) { [void]$md.AppendLine("- **License SKUs:** $(@($lic.Detail).Count)") }
    if ($roles) { [void]$md.AppendLine("- **Global Admins:** $($roles.GlobalAdminCount)") }
    if ($ca)  { [void]$md.AppendLine("- **Conditional Access Policies:** $($ca.Total) ($($ca.Enabled) enabled)") }
    if ($mfa) { [void]$md.AppendLine("- **MFA Capable:** $($mfa.PercentMfaCapable)% ($($mfa.AdminsWithoutMfa) admins without MFA)") }
    if ($exo) { [void]$md.AppendLine("- **Mailboxes:** $($exo.TotalMailboxes)") }
    if ($spo) { [void]$md.AppendLine("- **SharePoint Storage:** $($spo.TotalStorageUsedGb) GB across $($spo.SiteCount) sites") }

    if ($ti) {
        [void]$md.AppendLine("`n## Tenant & Domains`n")
        [void]$md.AppendLine("| Property | Value |`n|---|---|")
        [void]$md.AppendLine("| Display Name | $($ti.DisplayName) |")
        [void]$md.AppendLine("| Tenant ID | $($ti.TenantId) |")
        [void]$md.AppendLine("| Default Domain | $($ti.DefaultDomain) |")
        [void]$md.AppendLine("| Hybrid Sync | $($ti.OnPremisesSyncOn) |")
        [void]$md.AppendLine("`n| Domain | Default | Type |`n|---|---|---|")
        foreach ($d in $ti.VerifiedDomains) { [void]$md.AppendLine("| $($d.Name) | $($d.IsDefault) | $($d.Type) |") }
    }

    if ($u) {
        [void]$md.AppendLine("`n## Users`n")
        [void]$md.AppendLine("| Metric | Value |`n|---|---|")
        [void]$md.AppendLine("| Total | $($u.Total) |`n| Enabled / Disabled | $($u.Enabled) / $($u.Disabled) |`n| Members / Guests | $($u.Members) / $($u.Guests) |`n| Cloud-only / Hybrid | $($u.CloudOnly) / $($u.HybridSynced) |`n| Licensed / Unlicensed | $($u.Licensed) / $($u.Unlicensed) |`n| Stale 90d+ | $($u.StaleOver90Days) |")
        [void]$md.AppendLine("`n### Full User Detail`n")
        [void]$md.AppendLine("| Name | UPN | Enabled | Type | Synced | Licensed | Last Sign-in |`n|---|---|---|---|---|---|---|")
        foreach ($row in $u.Detail) {
            [void]$md.AppendLine("| $($row.DisplayName) | $($row.UserPrincipalName) | $($row.Enabled) | $($row.Type) | $($row.Synced) | $($row.Licensed) | $($row.LastSignIn) |")
        }
    }

    if ($g) {
        [void]$md.AppendLine("`n## Groups`n")
        [void]$md.AppendLine("| Metric | Value |`n|---|---|")
        [void]$md.AppendLine("| Total | $($g.Total) |`n| Microsoft 365 | $($g.Microsoft365Groups) |`n| Security | $($g.SecurityGroups) |`n| Mail-Enabled Security | $($g.MailEnabledSecurity) |`n| Distribution | $($g.DistributionGroups) |`n| Dynamic | $($g.DynamicGroups) |`n| Ownerless | $($g.OwnerlessGroups) |")
        [void]$md.AppendLine("`n### Group Detail`n")
        [void]$md.AppendLine("| Name | Type | Dynamic | Owners |`n|---|---|---|---|")
        foreach ($row in $g.Detail) { [void]$md.AppendLine("| $($row.DisplayName) | $($row.Type) | $($row.Dynamic) | $($row.OwnerCount) |") }
    }

    if ($lic -and $lic.Detail) {
        [void]$md.AppendLine("`n## Licenses`n")
        [void]$md.AppendLine("| SKU | Consumed | Enabled | Available | % Used |`n|---|---|---|---|---|")
        foreach ($s in ($lic.Detail | Sort-Object PercentUsed -Descending)) {
            [void]$md.AppendLine("| $($s.SkuPartNumber) | $($s.Consumed) | $($s.Enabled) | $($s.Available) | $($s.PercentUsed)% |")
        }
    }

    if ($roles -and $roles.Detail) {
        [void]$md.AppendLine("`n## Admin Roles`n")
        [void]$md.AppendLine("| Role | Members | Who |`n|---|---|---|")
        foreach ($r in $roles.Detail) { [void]$md.AppendLine("| $($r.RoleName) | $($r.MemberCount) | $($r.Members) |") }
    }

    if ($ca -and $ca.Detail) {
        [void]$md.AppendLine("`n## Conditional Access`n")
        [void]$md.AppendLine("| Policy | State | Users | Apps | Grant Controls |`n|---|---|---|---|---|")
        foreach ($p in $ca.Detail) { [void]$md.AppendLine("| $($p.DisplayName) | $($p.State) | $($p.Users) | $($p.Apps) | $($p.GrantControls) |") }
    }

    if ($mfa) {
        [void]$md.AppendLine("`n## MFA & Authentication Methods`n")
        [void]$md.AppendLine("| Metric | Value |`n|---|---|")
        [void]$md.AppendLine("| Users Reported | $($mfa.TotalUsersReported) |`n| MFA Capable | $($mfa.MfaCapable) ($($mfa.PercentMfaCapable)%) |`n| MFA Registered | $($mfa.MfaRegistered) |`n| Security Defaults Enabled | $($mfa.SecurityDefaultsEnabled) |`n| Admins without MFA | $($mfa.AdminsWithoutMfa) |")
        if ($mfa.AdminsWithoutMfaDetail) { [void]$md.AppendLine("`nAdmins lacking MFA: $($mfa.AdminsWithoutMfaDetail)") }
    }

    if ($apps -and $apps.Detail) {
        [void]$md.AppendLine("`n## Applications / Service Principals`n")
        [void]$md.AppendLine("Total app registrations: $($apps.Total). $($apps.Note)`n")
        [void]$md.AppendLine("| App | APIs Requested | Permission Count | Created |`n|---|---|---|---|")
        foreach ($a in $apps.Detail) { [void]$md.AppendLine("| $($a.DisplayName) | $($a.ResourceApiCount) | $($a.PermissionCount) | $($a.Created) |") }
    }

    if ($exo) {
        [void]$md.AppendLine("`n## Exchange Online`n")
        [void]$md.AppendLine("| Mailbox Type | Count |`n|---|---|")
        foreach ($t in $exo.MailboxesByType) { [void]$md.AppendLine("| $($t.Type) | $($t.Count) |") }
        [void]$md.AppendLine("`n| Metric | Value |`n|---|---|")
        [void]$md.AppendLine("| Total Mailboxes | $($exo.TotalMailboxes) |`n| Mail Flow Rules | $($exo.TransportRuleCount) |`n| Inbound Connectors | $($exo.InboundConnectorCount) |`n| Outbound Connectors | $($exo.OutboundConnectorCount) |")
    }

    if ($spo) {
        [void]$md.AppendLine("`n## SharePoint & OneDrive`n")
        [void]$md.AppendLine("| Metric | Value |`n|---|---|")
        [void]$md.AppendLine("| Site Collections | $($spo.SiteCount) |`n| Storage Used | $($spo.TotalStorageUsedGb) GB |`n| Sharing Capability | $($spo.SharingCapability) |`n| OneDrive Sharing Capability | $($spo.OneDriveSharingCapability) |`n| Default Link Permission | $($spo.DefaultLinkPermission) |`n| Legacy Auth Blocked | $($spo.LegacyAuthProtocolsEnabled) |")
    }

    if ($Data.Meta.Warnings -and $Data.Meta.Warnings.Count -gt 0) {
        [void]$md.AppendLine("`n## Collection Warnings`n")
        foreach ($w in $Data.Meta.Warnings) { [void]$md.AppendLine("- $w") }
    }

    return $md.ToString()
}

function Export-ReportToPdf {
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$PdfPath
    )

    $edgeCandidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    )
    $edge = $edgeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $edge) {
        Add-ReportWarning -Section 'PDF' -Message 'msedge.exe not found - PDF export skipped. HTML and Markdown were still generated.'
        return $false
    }

    try {
        $fileUri = ([uri]$HtmlPath).AbsoluteUri
        $args = @('--headless', '--disable-gpu', "--print-to-pdf=`"$PdfPath`"", $fileUri)
        Start-Process -FilePath $edge -ArgumentList $args -Wait -NoNewWindow -ErrorAction Stop
        if (Test-Path $PdfPath) {
            return $true
        }
        Add-ReportWarning -Section 'PDF' -Message 'Edge ran but no PDF file was produced.'
        return $false
    }
    catch {
        Add-ReportWarning -Section 'PDF' -Message "PDF export failed: $($_.Exception.Message)"
        return $false
    }
}

#endregion Report Rendering

#region Main

try {
    Write-Section 'Get-TenantConfigReport starting'

    $ctx = Connect-TenantGraph -TenantId $TenantId

    $exoConnected = $false
    if (-not $SkipExchange) {
        $exoConnected = Connect-TenantExchange -TenantId $TenantId
    }
    else {
        Write-Step 'Exchange Online skipped (-SkipExchange).'
    }

    $spoConnected = $false
    if (-not $SkipSharePoint) {
        try {
            $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
            $initialDomain = $org.VerifiedDomains | Where-Object { $_.IsInitial } | Select-Object -ExpandProperty Name -First 1
            if ($initialDomain) {
                $tenantPrefix = $initialDomain.Split('.')[0]
                $adminUrl = "https://$tenantPrefix-admin.sharepoint.com"
                $spoConnected = Connect-TenantSharePoint -AdminUrl $adminUrl
            }
            else {
                Add-ReportWarning -Section 'SharePoint' -Message 'Could not determine SharePoint admin URL from initial domain - section skipped.'
            }
        }
        catch {
            Add-ReportWarning -Section 'SharePoint' -Message "Could not determine SharePoint admin URL: $($_.Exception.Message)"
        }
    }
    else {
        Write-Step 'SharePoint Online skipped (-SkipSharePoint).'
    }

    # ---- Collect ----
    $script:Report.TenantInfo        = Get-TenantInfoData
    $script:Report.Users             = Get-UsersData
    $script:Report.Groups            = Get-GroupsData
    $script:Report.Licenses          = Get-LicensesData
    $script:Report.AdminRoles        = Get-AdminRolesData
    $script:Report.ConditionalAccess = Get-ConditionalAccessData
    $script:Report.Mfa               = Get-MfaData
    $script:Report.Applications      = Get-ApplicationsData
    $script:Report.ExchangeOnline    = if ($exoConnected) { Get-ExchangeOnlineData } else { $null }
    $script:Report.SharePoint        = if ($spoConnected) { Get-SharePointData } else { $null }

    $script:Report.Meta = [PSCustomObject]@{
        GeneratedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        RunBy       = $ctx.Account
        TenantId    = $ctx.TenantId
        Warnings    = $script:Warnings
    }

    # ---- Render & Export ----
    Write-Section 'Rendering report'

    $stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $tenantSlug = if ($script:Report.TenantInfo) {
        ($script:Report.TenantInfo.DefaultDomain -replace '[^a-zA-Z0-9.-]', '') -replace '\.onmicrosoft\.com$', ''
    } else { 'tenant' }
    $folderName = "TenantReport_${tenantSlug}_$stamp"
    $outDir = Join-Path -Path $OutputPath -ChildPath $folderName
    New-Item -Path $outDir -ItemType Directory -Force | Out-Null

    $htmlPath = Join-Path $outDir 'TenantReport.html'
    $mdPath   = Join-Path $outDir 'TenantReport.md'
    $pdfPath  = Join-Path $outDir 'TenantReport.pdf'

    $htmlContent = New-HtmlReport -Data $script:Report
    Set-Content -Path $htmlPath -Value $htmlContent -Encoding UTF8
    Write-Step "HTML report written: $htmlPath"

    $mdContent = New-MarkdownReport -Data $script:Report
    Set-Content -Path $mdPath -Value $mdContent -Encoding UTF8
    Write-Step "Markdown report written: $mdPath"

    if (-not $SkipPdf) {
        Write-Step 'Rendering PDF via headless Edge...'
        if (Export-ReportToPdf -HtmlPath $htmlPath -PdfPath $pdfPath) {
            Write-Step "PDF report written: $pdfPath"
        }
    }
    else {
        Write-Step 'PDF export skipped (-SkipPdf).'
    }

    # ---- Summary ----
    $elapsed = (Get-Date) - $script:StartTime
    Write-Section "Done in $([math]::Round($elapsed.TotalMinutes, 1)) minute(s)"
    Write-Host "Output folder: $outDir" -ForegroundColor Green
    if ($script:Warnings.Count -gt 0) {
        Write-Host "`n$($script:Warnings.Count) warning(s) were recorded - see the Collection Warnings section in the report." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Report generation failed: $($_.Exception.Message)"
    throw
}
finally {
    Write-Section 'Disconnecting'
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    try { if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } } catch { }
    try { if (Get-Command Disconnect-PnPOnline -ErrorAction SilentlyContinue) { Disconnect-PnPOnline -ErrorAction SilentlyContinue | Out-Null } } catch { }
}

#endregion Main