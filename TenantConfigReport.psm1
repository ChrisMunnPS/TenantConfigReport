#region Setup

function Initialize-TenantReportState {
    <#
    .SYNOPSIS
        Resets module-scoped report state. Call once at the start of each Invoke-TenantConfigReport run
        (and in test setup) so repeated runs/tests in the same session don't inherit stale state.
    #>
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
        SecureScore       = $null
        UserSettings      = $null
        Drift             = $null
    }
    $script:Warnings = [System.Collections.Generic.List[string]]::new()
}

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

function Get-RedactionHash {
    <#
    .SYNOPSIS
        Produces a short, deterministic, non-reversible placeholder for a sensitive string (email,
        GUID, domain name, etc.) using SHA-256 - never a raw substring of the original value, since a
        substring of a "redacted" value is still a leak of real data.
    .PARAMETER Value
        The real value to redact (e.g. an email address or object ID).
    .PARAMETER Length
        How many hex characters of the hash to return. Default 8.
    #>
    param(
        [Parameter(Mandatory)][string]$Value,
        [int]$Length = 8
    )
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        return (($hashBytes | ForEach-Object { $_.ToString('X2') }) -join '').Substring(0, $Length).ToLower()
    }
    finally {
        $sha256.Dispose()
    }
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
        'Microsoft.Graph.Reports',
        'Microsoft.Graph.Security'
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
        'Directory.Read.All',
        'SecurityEvents.Read.All'
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
    param([switch]$Redact)

    Write-Section 'Collecting tenant / domain information'
    try {
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $domains = $org.VerifiedDomains

        # Stable per-run placeholder suffix derived from a SHA-256 hash of the tenant's real ID (never a
        # raw substring of it), so redacted names/domains stay consistent across the report without ever
        # printing any actual fragment of the real tenant ID or name anywhere they'd be readable.
        $suffix = if ($org.Id) { Get-RedactionHash -Value $org.Id -Length 8 } else { 'unknown' }

        $techEmails = if ($Redact) {
            ($org.TechnicalNotificationMails | ForEach-Object { "admin-$(Get-RedactionHash -Value $_ -Length 6)@redacted.example" }) -join ', '
        } else {
            ($org.TechnicalNotificationMails -join ', ')
        }

        [PSCustomObject]@{
            DisplayName       = if ($Redact) { "Tenant-$($suffix.ToUpper())" } else { $org.DisplayName }
            TenantId          = if ($Redact) { "redacted-$suffix" } else { $org.Id }
            DefaultDomain     = if ($Redact) { "redacted-$suffix.example" } else { ($domains | Where-Object { $_.IsDefault } | Select-Object -ExpandProperty Name -First 1) }
            VerifiedDomains   = $domains | ForEach-Object {
                [PSCustomObject]@{
                    Name      = if ($Redact) { "redacted-$suffix-$(Get-RedactionHash -Value $_.Name -Length 4).example" } else { $_.Name }
                    IsDefault = $_.IsDefault
                    IsInitial = $_.IsInitial
                    Type      = $_.Type
                }
            }
            City              = $org.City
            Country           = $org.CountryLetterCode
            TechNotifyEmails  = $techEmails
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
    param([switch]$Redact)

    Write-Section 'Collecting user data (this can take a while on large tenants)'
    try {
        Write-Step 'Fetching users...'
        $allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, UserType, `
            OnPremisesSyncEnabled, AssignedLicenses, CreatedDateTime -ErrorAction Stop

        $enabled  = $allUsers | Where-Object { $_.AccountEnabled }
        $disabled = $allUsers | Where-Object { -not $_.AccountEnabled }
        $guests   = $allUsers | Where-Object { $_.UserType -eq 'Guest' }
        $members  = $allUsers | Where-Object { $_.UserType -eq 'Member' }
        $synced   = $allUsers | Where-Object { $_.OnPremisesSyncEnabled }
        $cloud    = $allUsers | Where-Object { -not $_.OnPremisesSyncEnabled }
        $licensed = $allUsers | Where-Object { $_.AssignedLicenses -and $_.AssignedLicenses.Count -gt 0 }
        $unlicensed = $allUsers | Where-Object { -not $_.AssignedLicenses -or $_.AssignedLicenses.Count -eq 0 }

        # Sign-in activity requires Entra ID P1/P2 and is fetched separately - a licensing gap here
        # (common on smaller tenants) should only cost the stale-account figure, not the whole section.
        $signInByUserId = @{}
        $staleAvailable = $true
        try {
            Write-Step 'Fetching sign-in activity (requires Entra ID P1/P2)...'
            $signInData = Get-MgUser -All -Property Id, SignInActivity -ErrorAction Stop
            foreach ($s in $signInData) { $signInByUserId[$s.Id] = $s.SignInActivity.LastSignInDateTime }
        }
        catch {
            $staleAvailable = $false
            Add-ReportWarning -Section 'Users' -Message "Sign-in activity unavailable (requires Entra ID P1/P2 licensing) - stale-account detection skipped: $($_.Exception.Message)"
        }

        $staleCutoff = (Get-Date).AddDays(-90)
        $staleCount = $null
        if ($staleAvailable) {
            $staleCount = @($enabled | Where-Object {
                $last = $signInByUserId[$_.Id]
                (-not $last) -or ([datetime]$last -lt $staleCutoff)
            }).Count
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
            StaleOver90Days  = $staleCount
            Detail           = $allUsers | ForEach-Object {
                [PSCustomObject]@{
                    DisplayName       = if ($Redact) { "User-$(Get-RedactionHash -Value $_.Id)" } else { $_.DisplayName }
                    UserPrincipalName = if ($Redact) { "user-$(Get-RedactionHash -Value $_.Id)@redacted.example" } else { $_.UserPrincipalName }
                    Enabled           = $_.AccountEnabled
                    Type              = $_.UserType
                    Synced            = [bool]$_.OnPremisesSyncEnabled
                    Licensed          = [bool]($_.AssignedLicenses -and $_.AssignedLicenses.Count -gt 0)
                    LastSignIn        = if ($staleAvailable) { $signInByUserId[$_.Id] } else { $null }
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
    param([switch]$Redact)

    Write-Section 'Collecting privileged role assignments'
    try {
        $roles = Get-MgDirectoryRole -All -ErrorAction Stop

        # Single bulk lookup instead of one Get-MgUser call per role member (was N+1).
        Write-Step 'Building user display-name lookup for role member resolution...'
        $userNameById = @{}
        try {
            Get-MgUser -All -Property Id, DisplayName -ErrorAction Stop | ForEach-Object { $userNameById[$_.Id] = $_.DisplayName }
        }
        catch {
            Add-ReportWarning -Section 'AdminRoles' -Message "Could not build user lookup for role member names - members will show as object IDs: $($_.Exception.Message)"
        }

        $detail = foreach ($role in $roles) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
            if ($members -and $members.Count -gt 0) {
                [PSCustomObject]@{
                    RoleName    = $role.DisplayName
                    MemberCount = $members.Count
                    Members     = ($members | ForEach-Object {
                        if ($Redact) { "Member-$(Get-RedactionHash -Value $_.Id)" }
                        elseif ($userNameById.ContainsKey($_.Id)) { $userNameById[$_.Id] }
                        else { "$($_.Id) (non-user principal or lookup unavailable)" }
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
    param([switch]$Redact)

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

        $adminsDetail = if ($Redact) {
            ($adminsNotMfaCapable | ForEach-Object { "Admin-$(Get-RedactionHash -Value $_.Id)" }) -join ', '
        } else {
            ($adminsNotMfaCapable | Select-Object -ExpandProperty UserPrincipalName) -join ', '
        }

        [PSCustomObject]@{
            TotalUsersReported     = $total
            MfaCapable              = $mfaCapable
            MfaRegistered           = $mfaRegistered
            PercentMfaCapable       = if ($total -gt 0) { [math]::Round(($mfaCapable / $total) * 100, 1) } else { 0 }
            AdminsWithoutMfa        = $adminsNotMfaCapable.Count
            AdminsWithoutMfaDetail  = $adminsDetail
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

        # Per-site external sharing audit: flag sites whose SharingCapability overrides the tenant default,
        # most-permissive first, since those are the ones worth reviewing individually.
        $sharingRank = @{ 'Disabled' = 0; 'ExistingExternalUserSharingOnly' = 1; 'ExternalUserSharingOnly' = 2; 'ExternalUserAndGuestSharing' = 3 }
        $siteOverrides = $sites |
            Where-Object { $_.SharingCapability -ne $tenant.SharingCapability } |
            ForEach-Object {
                [PSCustomObject]@{
                    Url               = $_.Url
                    Title             = $_.Title
                    SharingCapability = $_.SharingCapability
                    StorageUsedGb     = [math]::Round($_.StorageUsageCurrent / 1024, 2)
                    RankValue         = if ($sharingRank.ContainsKey([string]$_.SharingCapability)) { $sharingRank[[string]$_.SharingCapability] } else { -1 }
                }
            } |
            Sort-Object -Property RankValue -Descending |
            Select-Object -First 25

        [PSCustomObject]@{
            SiteCount             = $sites.Count
            TotalStorageUsedGb    = $totalStorageGb
            SharingCapability     = $tenant.SharingCapability
            OneDriveSharingCapability = $tenant.OneDriveSharingCapability
            DefaultLinkPermission = $tenant.DefaultLinkPermission
            LegacyAuthProtocolsEnabled = -not [bool]$tenant.LegacyAuthProtocolsEnabled
            SiteOverrideCount     = @($siteOverrides).Count
            SiteOverrides         = $siteOverrides
        }
    }
    catch {
        Add-ReportWarning -Section 'SharePoint' -Message $_.Exception.Message
        $null
    }
}

function Get-SecureScoreData {
    Write-Section 'Collecting Secure Score (Identity + Device)'
    try {
        $score = Get-MgSecuritySecureScore -Top 1 -ErrorAction Stop | Select-Object -First 1
        if (-not $score) {
            Add-ReportWarning -Section 'SecureScore' -Message 'No secure score data returned by Graph.'
            return $null
        }

        Write-Step 'Fetching control profile definitions for accurate max-score join...'
        $profiles = Get-MgSecuritySecureScoreControlProfile -All -ErrorAction SilentlyContinue
        $profileByName = @{}
        foreach ($p in $profiles) {
            if ($p.Id) { $profileByName[$p.Id] = $p }
        }

        $overallPct = if ($score.MaxScore -gt 0) { [math]::Round(($score.CurrentScore / $score.MaxScore) * 100, 1) } else { 0 }

        function Get-CategoryBreakdown {
            param([string]$Category, $ControlScores, $ProfileByName)

            $controls = $ControlScores | Where-Object { $_.ControlCategory -eq $Category }
            $detail = $controls | ForEach-Object {
                $ctrl = $_
                $maxScore = $null
                if ($ProfileByName.ContainsKey($ctrl.ControlName)) {
                    $maxScore = $ProfileByName[$ctrl.ControlName].MaxScore
                }
                $gap = if ($maxScore) { [math]::Round($maxScore - $ctrl.Score, 2) } else { $null }
                [PSCustomObject]@{
                    ControlName = $ctrl.ControlName
                    Description = $ctrl.Description
                    Score       = [math]::Round($ctrl.Score, 2)
                    MaxScore    = $maxScore
                    Gap         = $gap
                    Implemented = if ($maxScore) { $ctrl.Score -ge $maxScore } else { $null }
                }
            }
            $achieved = ($detail | Measure-Object -Property Score -Sum).Sum
            $maxKnown = ($detail | Where-Object { $_.MaxScore } | Measure-Object -Property MaxScore -Sum).Sum
            $pct = if ($maxKnown -gt 0) { [math]::Round(($achieved / $maxKnown) * 100, 1) } else { $null }
            $topOpportunities = $detail | Where-Object { $_.MaxScore -and -not $_.Implemented } | Sort-Object -Property Gap -Descending | Select-Object -First 10

            [PSCustomObject]@{
                Percent          = $pct
                ControlCount     = @($detail).Count
                TopOpportunities = $topOpportunities
                AllControls      = $detail | Sort-Object ControlName
            }
        }

        $identity = Get-CategoryBreakdown -Category 'Identity' -ControlScores $score.ControlScores -ProfileByName $profileByName
        $device   = Get-CategoryBreakdown -Category 'Device'   -ControlScores $score.ControlScores -ProfileByName $profileByName

        [PSCustomObject]@{
            OverallCurrentScore   = [math]::Round($score.CurrentScore, 1)
            OverallMaxScore       = [math]::Round($score.MaxScore, 1)
            OverallPercent        = $overallPct
            IdentityPercent       = $identity.Percent
            IdentityControlCount  = $identity.ControlCount
            TopOpportunities      = $identity.TopOpportunities
            AllIdentityControls   = $identity.AllControls
            DevicePercent         = $device.Percent
            DeviceControlCount    = $device.ControlCount
            DeviceTopOpportunities = $device.TopOpportunities
            AllDeviceControls     = $device.AllControls
            CreatedDateTime       = $score.CreatedDateTime
        }
    }
    catch {
        Add-ReportWarning -Section 'SecureScore' -Message $_.Exception.Message
        $null
    }
}

function Get-UserSettingsData {
    Write-Section 'Collecting User settings (Entra admin center: Users > User settings)'
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop | Select-Object -First 1
        $perms = $authPolicy.DefaultUserRolePermissions

        $groupCreationRestricted = $null
        try {
            $groupSetting = Get-MgGroupSetting -All -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -eq 'Group.Unified' } | Select-Object -First 1
            if ($groupSetting) {
                $enableGroupCreationVal = ($groupSetting.Values | Where-Object { $_.Name -eq 'EnableGroupCreation' }).Value
                $groupCreationRestricted = if ($null -ne $enableGroupCreationVal) { $enableGroupCreationVal -eq 'False' } else { $null }
            }
        }
        catch { }

        [PSCustomObject]@{
            UsersCanRegisterApps          = [bool]$perms.AllowedToCreateApps
            UsersCanCreateSecurityGroups  = [bool]$perms.AllowedToCreateSecurityGroups
            UsersCanCreateM365Groups      = if ($null -ne $groupCreationRestricted) { -not $groupCreationRestricted } else { $null }
            UsersCanCreateTenants         = [bool]$perms.AllowedToCreateTenants
            UsersCanReadOtherUsers        = [bool]$perms.AllowedToReadOtherUsers
            AdminsCanUseSspr              = [bool]$authPolicy.AllowedToUseSspr
            GuestInviteSetting            = $authPolicy.AllowInvitesFrom
            EmailVerifiedUsersCanJoin     = [bool]$authPolicy.AllowEmailVerifiedUsersToJoinOrganization
            LegacyMsolPowerShellBlocked   = [bool]$authPolicy.BlockMsolPowerShell
        }
    }
    catch {
        Add-ReportWarning -Section 'UserSettings' -Message $_.Exception.Message
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

function Get-ReportCss {
    <#
    .SYNOPSIS
        Loads the report's CSS from Templates/ReportStyles.css (sibling of this module file).
        Falls back to a minimal inline stylesheet if the template file can't be found, so the
        module still produces a readable (if plainer) report even if it's copied out on its own.
    #>
    $templatePath = Join-Path $PSScriptRoot 'Templates/ReportStyles.css'
    if (Test-Path $templatePath) {
        try {
            return (Get-Content -Path $templatePath -Raw -ErrorAction Stop)
        }
        catch {
            Add-ReportWarning -Section 'Rendering' -Message "Could not read $templatePath - using fallback styles: $($_.Exception.Message)"
        }
    }
    else {
        Add-ReportWarning -Section 'Rendering' -Message "Template file not found at $templatePath - using fallback styles."
    }
    return @'
:root { --bg:#0f172a; --panel:#fff; --panel-border:#e2e8f0; --text:#1e293b; --muted:#64748b; --good:#16a34a; --warn:#d97706; --bad:#dc2626; --bg-page:#f1f5f9; }
body { font-family: Segoe UI, Arial, sans-serif; margin:0; background:var(--bg-page); color:var(--text); }
header { background:var(--bg); color:#fff; padding:24px; } main { padding:24px; max-width:1100px; margin:0 auto; }
table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--panel-border); margin-top:10px; }
th, td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--panel-border); }
.pill { padding:2px 9px; border-radius:999px; font-size:11px; font-weight:600; }
.pill-good { background:#dcfce7; color:var(--good); } .pill-warn { background:#fef3c7; color:var(--warn); } .pill-bad { background:#fee2e2; color:var(--bad); }
'@
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
    $sscore = $Data.SecureScore
    $usettings = $Data.UserSettings

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Tenant Configuration Report$(if ($ti) { " - $($ti.DisplayName)" })</title>
<style>
$(Get-ReportCss)
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
  <a href="#securescore">Secure Score</a>
  <a href="#usersettings">User Settings</a>
  <a href="#drift">Change Since Last Run</a>
</nav>
<main>
"@)

    $narrative = New-NarrativeSummary -Data $Data
    [void]$sb.AppendLine("<div class=""card"" style=""margin-bottom:20px;""><div class=""label"">Executive Summary</div><p style=""margin:8px 0 0 0; font-size:14px; line-height:1.5;"">$([System.Net.WebUtility]::HtmlEncode($narrative))</p></div>")

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
    if ($sscore) {
        $ssCls = if ($sscore.OverallPercent -ge 70) { 'pill-good' } elseif ($sscore.OverallPercent -ge 40) { 'pill-warn' } else { 'pill-bad' }
        $idPctText = if ($null -ne $sscore.IdentityPercent) { "$($sscore.IdentityPercent)%" } else { 'N/A' }
        $devPctText = if ($null -ne $sscore.DevicePercent) { "$($sscore.DevicePercent)%" } else { 'N/A' }
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">Secure Score</div><div class="value"><span class="pill $ssCls">$($sscore.OverallPercent)%</span></div><div class="sub">Identity: $idPctText &middot; Device: $devPctText</div></div>
"@)
    }
    if ($usettings) {
        $riskyCount = @(
            $usettings.UsersCanRegisterApps, $usettings.UsersCanCreateSecurityGroups, $usettings.UsersCanCreateTenants
        ) | Where-Object { $_ -eq $true } | Measure-Object | Select-Object -ExpandProperty Count
        $usCls = if ($riskyCount -eq 0) { 'pill-good' } elseif ($riskyCount -le 1) { 'pill-warn' } else { 'pill-bad' }
        [void]$sb.AppendLine(@"
<div class="card"><div class="label">User Settings</div><div class="value"><span class="pill $usCls">$riskyCount</span></div><div class="sub">permissive default(s) enabled</div></div>
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
        if ($spo.SiteOverrides -and $spo.SiteOverrides.Count -gt 0) {
            [void]$sb.AppendLine("<p class=""note"">$($spo.SiteOverrideCount) site(s) override the tenant-default sharing capability (showing up to 25, most permissive first):</p>")
            [void]$sb.AppendLine('<table><tr><th>Site</th><th>Sharing Capability</th><th>Storage (GB)</th></tr>')
            foreach ($s in $spo.SiteOverrides) {
                [void]$sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($s.Title)) <span class=""note"">($([System.Net.WebUtility]::HtmlEncode($s.Url)))</span></td><td>$($s.SharingCapability)</td><td>$($s.StorageUsedGb)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        else {
            [void]$sb.AppendLine('<p class="note">No sites override the tenant-default sharing capability.</p>')
        }
    } else {
        [void]$sb.AppendLine('<div class="skipped">SharePoint section skipped or unavailable - see warnings.</div>')
    }

    # ---- Secure Score (Identity + Device) ----
    [void]$sb.AppendLine('<h2 id="securescore">Secure Score - Identity &amp; Device</h2>')
    if ($sscore) {
        $idPctText = if ($null -ne $sscore.IdentityPercent) { "$($sscore.IdentityPercent)%" } else { 'N/A (max-score data unavailable for some controls)' }
        $devPctText2 = if ($null -ne $sscore.DevicePercent) { "$($sscore.DevicePercent)%" } else { 'N/A (max-score data unavailable for some controls)' }
        [void]$sb.AppendLine(@"
<table>
<tr><th>Overall Secure Score</th><td>$($sscore.OverallCurrentScore) / $($sscore.OverallMaxScore) ($($sscore.OverallPercent)%)</td></tr>
<tr><th>Identity Category Score</th><td>$idPctText</td></tr>
<tr><th>Identity Controls Tracked</th><td>$($sscore.IdentityControlCount)</td></tr>
<tr><th>Device Category Score</th><td>$devPctText2</td></tr>
<tr><th>Device Controls Tracked</th><td>$($sscore.DeviceControlCount)</td></tr>
<tr><th>Score Snapshot Date</th><td>$($sscore.CreatedDateTime)</td></tr>
</table>
"@)
        if ($sscore.TopOpportunities -and $sscore.TopOpportunities.Count -gt 0) {
            [void]$sb.AppendLine('<p class="note">Top unimplemented Identity controls, ranked by points available:</p>')
            [void]$sb.AppendLine('<table><tr><th>Control</th><th>Description</th><th>Current</th><th>Max</th><th>Points Available</th></tr>')
            foreach ($c in $sscore.TopOpportunities) {
                [void]$sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($c.ControlName))</td><td>$([System.Net.WebUtility]::HtmlEncode($c.Description))</td><td>$($c.Score)</td><td>$($c.MaxScore)</td><td>$($c.Gap)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        else {
            [void]$sb.AppendLine('<p class="note">No outstanding Identity control opportunities found (or max-score data was unavailable to calculate gaps).</p>')
        }

        if ($sscore.DeviceTopOpportunities -and $sscore.DeviceTopOpportunities.Count -gt 0) {
            [void]$sb.AppendLine('<p class="note">Top unimplemented Device controls, ranked by points available:</p>')
            [void]$sb.AppendLine('<table><tr><th>Control</th><th>Description</th><th>Current</th><th>Max</th><th>Points Available</th></tr>')
            foreach ($c in $sscore.DeviceTopOpportunities) {
                [void]$sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($c.ControlName))</td><td>$([System.Net.WebUtility]::HtmlEncode($c.Description))</td><td>$($c.Score)</td><td>$($c.MaxScore)</td><td>$($c.Gap)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        else {
            [void]$sb.AppendLine('<p class="note">No outstanding Device control opportunities found (or max-score data was unavailable to calculate gaps).</p>')
        }
    } else {
        [void]$sb.AppendLine('<div class="skipped">Secure Score data unavailable - see warnings.</div>')
    }

    # ---- User Settings ----
    [void]$sb.AppendLine('<h2 id="usersettings">User Settings</h2>')
    if ($usettings) {
        function Get-SettingPill {
            param($Value, [bool]$TrueIsRisky = $true)
            if ($null -eq $Value) { return '<span class="pill">unknown</span>' }
            $cls = if ($Value -eq $TrueIsRisky) { 'pill-warn' } else { 'pill-good' }
            return "<span class=""pill $cls"">$Value</span>"
        }
        [void]$sb.AppendLine(@"
<p class="note">Mirrors the Entra admin center &rarr; Users &rarr; User settings blade. Amber flags a permissive default Microsoft recommends reviewing.</p>
<table>
<tr><th>Setting</th><th>Value</th></tr>
<tr><td>Users can register applications</td><td>$(Get-SettingPill $usettings.UsersCanRegisterApps)</td></tr>
<tr><td>Users can create security groups</td><td>$(Get-SettingPill $usettings.UsersCanCreateSecurityGroups)</td></tr>
<tr><td>Users can create Microsoft 365 groups</td><td>$(Get-SettingPill $usettings.UsersCanCreateM365Groups)</td></tr>
<tr><td>Users can create tenants</td><td>$(Get-SettingPill $usettings.UsersCanCreateTenants)</td></tr>
<tr><td>Users can read other users' full profiles</td><td>$(Get-SettingPill $usettings.UsersCanReadOtherUsers)</td></tr>
<tr><td>Admins can use Self-Service Password Reset</td><td>$(Get-SettingPill $usettings.AdminsCanUseSspr $false)</td></tr>
<tr><td>Guest invite setting</td><td>$($usettings.GuestInviteSetting)</td></tr>
<tr><td>Email-verified users can join org</td><td>$(Get-SettingPill $usettings.EmailVerifiedUsersCanJoin)</td></tr>
<tr><td>Legacy MSOL PowerShell blocked</td><td>$(Get-SettingPill $usettings.LegacyMsolPowerShellBlocked $false)</td></tr>
</table>
"@)
    } else {
        [void]$sb.AppendLine('<div class="skipped">User settings data unavailable - see warnings.</div>')
    }

    # ---- Change Since Last Run ----
    [void]$sb.AppendLine('<h2 id="drift">Change Since Last Run</h2>')
    $drift = $Data.Drift
    if ($drift -and $drift.PreviousCapturedAt) {
        if ($drift.Changes -and $drift.Changes.Count -gt 0) {
            [void]$sb.AppendLine("<p class=""note"">Compared against the run captured $($drift.PreviousCapturedAt):</p><table><tr><th>Change</th></tr>")
            foreach ($c in $drift.Changes) { [void]$sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($c))</td></tr>") }
            [void]$sb.AppendLine('</table>')
        } else {
            [void]$sb.AppendLine("<p class=""note"">No change in tracked metrics since the run captured $($drift.PreviousCapturedAt).</p>")
        }
    } else {
        [void]$sb.AppendLine('<div class="skipped">No prior run found for this tenant in this output location - this is the baseline. Future runs will show drift here.</div>')
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
    $sscore = $Data.SecureScore
    $usettings = $Data.UserSettings

    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine("# Tenant Configuration Report$(if ($ti) { " - $($ti.DisplayName)" })")
    [void]$md.AppendLine("`nGenerated $($Data.Meta.GeneratedAt) by $($Data.Meta.RunBy)  ")
    [void]$md.AppendLine("Tenant ID: $($Data.Meta.TenantId)`n")

    $narrative = New-NarrativeSummary -Data $Data
    [void]$md.AppendLine("> **Executive Summary:** $narrative`n")

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
    if ($sscore) { [void]$md.AppendLine("- **Secure Score:** $($sscore.OverallPercent)% overall, Identity: $(if ($null -ne $sscore.IdentityPercent) { "$($sscore.IdentityPercent)%" } else { 'N/A' }), Device: $(if ($null -ne $sscore.DevicePercent) { "$($sscore.DevicePercent)%" } else { 'N/A' })") }

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
        if ($spo.SiteOverrides -and $spo.SiteOverrides.Count -gt 0) {
            [void]$md.AppendLine("`n### Sites Overriding Tenant-Default Sharing ($($spo.SiteOverrideCount) total, showing up to 25)`n")
            [void]$md.AppendLine("| Site | URL | Sharing Capability | Storage (GB) |`n|---|---|---|---|")
            foreach ($s in $spo.SiteOverrides) {
                [void]$md.AppendLine("| $($s.Title) | $($s.Url) | $($s.SharingCapability) | $($s.StorageUsedGb) |")
            }
        }
    }

    if ($sscore) {
        [void]$md.AppendLine("`n## Secure Score - Identity & Device`n")
        $idPctText = if ($null -ne $sscore.IdentityPercent) { "$($sscore.IdentityPercent)%" } else { 'N/A' }
        $devPctText = if ($null -ne $sscore.DevicePercent) { "$($sscore.DevicePercent)%" } else { 'N/A' }
        [void]$md.AppendLine("| Metric | Value |`n|---|---|")
        [void]$md.AppendLine("| Overall Score | $($sscore.OverallCurrentScore) / $($sscore.OverallMaxScore) ($($sscore.OverallPercent)%) |`n| Identity Category | $idPctText |`n| Identity Controls Tracked | $($sscore.IdentityControlCount) |`n| Device Category | $devPctText |`n| Device Controls Tracked | $($sscore.DeviceControlCount) |`n| Snapshot Date | $($sscore.CreatedDateTime) |")
        if ($sscore.TopOpportunities -and $sscore.TopOpportunities.Count -gt 0) {
            [void]$md.AppendLine("`n### Top Unimplemented Identity Controls`n")
            [void]$md.AppendLine("| Control | Description | Current | Max | Points Available |`n|---|---|---|---|---|")
            foreach ($c in $sscore.TopOpportunities) {
                [void]$md.AppendLine("| $($c.ControlName) | $($c.Description) | $($c.Score) | $($c.MaxScore) | $($c.Gap) |")
            }
        }
        if ($sscore.DeviceTopOpportunities -and $sscore.DeviceTopOpportunities.Count -gt 0) {
            [void]$md.AppendLine("`n### Top Unimplemented Device Controls`n")
            [void]$md.AppendLine("| Control | Description | Current | Max | Points Available |`n|---|---|---|---|---|")
            foreach ($c in $sscore.DeviceTopOpportunities) {
                [void]$md.AppendLine("| $($c.ControlName) | $($c.Description) | $($c.Score) | $($c.MaxScore) | $($c.Gap) |")
            }
        }
    }

    if ($usettings) {
        [void]$md.AppendLine("`n## User Settings`n")
        [void]$md.AppendLine("Mirrors Entra admin center -> Users -> User settings.`n")
        [void]$md.AppendLine("| Setting | Value |`n|---|---|")
        [void]$md.AppendLine("| Users can register applications | $($usettings.UsersCanRegisterApps) |")
        [void]$md.AppendLine("| Users can create security groups | $($usettings.UsersCanCreateSecurityGroups) |")
        [void]$md.AppendLine("| Users can create Microsoft 365 groups | $($usettings.UsersCanCreateM365Groups) |")
        [void]$md.AppendLine("| Users can create tenants | $($usettings.UsersCanCreateTenants) |")
        [void]$md.AppendLine("| Users can read other users' full profiles | $($usettings.UsersCanReadOtherUsers) |")
        [void]$md.AppendLine("| Admins can use SSPR | $($usettings.AdminsCanUseSspr) |")
        [void]$md.AppendLine("| Guest invite setting | $($usettings.GuestInviteSetting) |")
        [void]$md.AppendLine("| Email-verified users can join org | $($usettings.EmailVerifiedUsersCanJoin) |")
        [void]$md.AppendLine("| Legacy MSOL PowerShell blocked | $($usettings.LegacyMsolPowerShellBlocked) |")
    }

    $drift = $Data.Drift
    [void]$md.AppendLine("`n## Change Since Last Run`n")
    if ($drift -and $drift.PreviousCapturedAt) {
        if ($drift.Changes -and $drift.Changes.Count -gt 0) {
            [void]$md.AppendLine("Compared against the run captured $($drift.PreviousCapturedAt):`n")
            foreach ($c in $drift.Changes) { [void]$md.AppendLine("- $c") }
        } else {
            [void]$md.AppendLine("No change in tracked metrics since the run captured $($drift.PreviousCapturedAt).")
        }
    } else {
        [void]$md.AppendLine('No prior run found for this tenant in this output location - this is the baseline.')
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

function New-NarrativeSummary {
    param([Parameter(Mandatory)][hashtable]$Data)

    $u    = $Data.Users
    $roles = $Data.AdminRoles
    $lic  = $Data.Licenses
    $mfa  = $Data.Mfa
    $ca   = $Data.ConditionalAccess
    $usettings = $Data.UserSettings
    $sscore = $Data.SecureScore

    # Informational lead - not a concern, just orients the reader. Kept separate from $points
    # so the "N item(s) worth a closer look" count below only reflects actual concerns.
    $overview = if ($u) { "$(Format-Number $u.Total) users ($(Format-Number $u.Enabled) enabled, $(Format-Number $u.Guests) guests)." } else { $null }

    $points = [System.Collections.Generic.List[string]]::new()

    if ($u -and $null -ne $u.StaleOver90Days -and $u.StaleOver90Days -gt 0) {
        $points.Add("$(Format-Number $u.StaleOver90Days) enabled account(s) with no sign-in in 90+ days")
    }
    if ($roles) {
        if ($roles.GlobalAdminCount -lt 2) {
            $points.Add("only $($roles.GlobalAdminCount) Global Admin(s) - below the recommended minimum of 2")
        }
        elseif ($roles.GlobalAdminCount -gt 4) {
            $points.Add("$($roles.GlobalAdminCount) Global Admins - worth reviewing against the recommended 2-4 range")
        }
    }
    if ($mfa -and $mfa.AdminsWithoutMfa -gt 0) {
        $points.Add("$($mfa.AdminsWithoutMfa) admin account(s) without MFA registered")
    }
    if ($lic -and $lic.Detail) {
        $near = @($lic.Detail | Where-Object { $_.NearLimit })
        if ($near.Count -gt 0) {
            $points.Add("$($near.Count) license SKU(s) at or near capacity ($(($near | Select-Object -ExpandProperty SkuPartNumber) -join ', '))")
        }
    }
    if ($ca -and $ca.Total -eq 0) {
        $points.Add('no Conditional Access policies configured')
    }
    if ($usettings) {
        $permissive = @(
            @{ Name = 'app registration'; Value = $usettings.UsersCanRegisterApps }
            @{ Name = 'security group creation'; Value = $usettings.UsersCanCreateSecurityGroups }
            @{ Name = 'tenant creation'; Value = $usettings.UsersCanCreateTenants }
        ) | Where-Object { $_.Value -eq $true } | ForEach-Object { $_.Name }
        if ($permissive.Count -gt 0) {
            $points.Add("permissive user settings still enabled: $($permissive -join ', ')")
        }
    }
    if ($sscore -and $sscore.OverallPercent -lt 50) {
        $points.Add("overall Secure Score is low at $($sscore.OverallPercent)%")
    }

    if ($points.Count -eq 0) {
        $concernText = 'No significant configuration concerns were identified in the areas this report covers.'
    }
    else {
        $concernText = "This tenant has $($points.Count) item(s) worth a closer look: " + ($points -join '; ') + '.'
    }

    if ($overview) { return "$overview $concernText" }
    return $concernText
}

function Get-DriftSnapshotPath {
    param([Parameter(Mandatory)][string]$OutputPath, [Parameter(Mandatory)][string]$TenantId)
    $historyDir = Join-Path $OutputPath '.trc-history'
    if (-not (Test-Path $historyDir)) { New-Item -Path $historyDir -ItemType Directory -Force | Out-Null }
    return Join-Path $historyDir "$TenantId.json"
}

function Get-CurrentMetricsSnapshot {
    param([Parameter(Mandatory)][hashtable]$Data)

    [PSCustomObject]@{
        CapturedAt          = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        GlobalAdminCount    = if ($Data.AdminRoles) { $Data.AdminRoles.GlobalAdminCount } else { $null }
        ConditionalAccessTotal = if ($Data.ConditionalAccess) { $Data.ConditionalAccess.Total } else { $null }
        SecureScorePercent  = if ($Data.SecureScore) { $Data.SecureScore.OverallPercent } else { $null }
        LicensesNearLimit   = if ($Data.Licenses -and $Data.Licenses.Detail) { @($Data.Licenses.Detail | Where-Object { $_.NearLimit }).Count } else { $null }
        UserTotal           = if ($Data.Users) { $Data.Users.Total } else { $null }
        MfaPercent          = if ($Data.Mfa) { $Data.Mfa.PercentMfaCapable } else { $null }
    }
}

function Get-DriftComparison {
    param([Parameter(Mandatory)][PSCustomObject]$Previous, [Parameter(Mandatory)][PSCustomObject]$Current)

    $lines = [System.Collections.Generic.List[string]]::new()
    $fields = @(
        @{ Name = 'GlobalAdminCount'; Label = 'Global Admins' }
        @{ Name = 'ConditionalAccessTotal'; Label = 'Conditional Access policies' }
        @{ Name = 'SecureScorePercent'; Label = 'Secure Score'; Suffix = '%' }
        @{ Name = 'LicensesNearLimit'; Label = 'License SKUs near limit' }
        @{ Name = 'UserTotal'; Label = 'Total users' }
        @{ Name = 'MfaPercent'; Label = 'MFA capable'; Suffix = '%' }
    )
    foreach ($f in $fields) {
        $prevVal = $Previous.($f.Name)
        $curVal  = $Current.($f.Name)
        if ($null -ne $prevVal -and $null -ne $curVal -and $prevVal -ne $curVal) {
            $suffix = if ($f.Suffix) { $f.Suffix } else { '' }
            $lines.Add("$($f.Label): $prevVal$suffix -> $curVal$suffix")
        }
    }
    return @{
        PreviousCapturedAt = $Previous.CapturedAt
        Changes            = $lines
    }
}

#endregion Report Rendering

#region Orchestration

function Invoke-TenantConfigReport {
    <#
    .SYNOPSIS
        Connects to a Microsoft 365 tenant and produces the full HTML/Markdown/PDF configuration report.
        This is the function the launcher script (Get-TenantConfigReport.ps1) calls; see that script's
        comment-based help for full parameter documentation - the parameters here are identical.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$OutputPath = (Get-Location).Path,
        [Parameter()][string]$TenantId,
        [Parameter()][switch]$SkipExchange,
        [Parameter()][switch]$SkipSharePoint,
        [Parameter()][switch]$SkipPdf,
        [Parameter()][switch]$Redact
    )

    $ErrorActionPreference = 'Stop'
    Initialize-TenantReportState

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
        $script:Report.TenantInfo        = Get-TenantInfoData -Redact:$Redact
        $script:Report.Users             = Get-UsersData -Redact:$Redact
        $script:Report.Groups            = Get-GroupsData
        $script:Report.Licenses          = Get-LicensesData
        $script:Report.AdminRoles        = Get-AdminRolesData -Redact:$Redact
        $script:Report.ConditionalAccess = Get-ConditionalAccessData
        $script:Report.Mfa               = Get-MfaData -Redact:$Redact
        $script:Report.Applications      = Get-ApplicationsData
        $script:Report.ExchangeOnline    = if ($exoConnected) { Get-ExchangeOnlineData } else { $null }
        $script:Report.SharePoint        = if ($spoConnected) { Get-SharePointData } else { $null }
        $script:Report.SecureScore       = Get-SecureScoreData
        $script:Report.UserSettings      = Get-UserSettingsData

        $script:Report.Meta = [PSCustomObject]@{
            GeneratedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            RunBy       = if ($Redact) { "admin-$(Get-RedactionHash -Value $ctx.Account)@redacted.example" } else { $ctx.Account }
            TenantId    = if ($Redact) { $script:Report.TenantInfo.TenantId } else { $ctx.TenantId }
            Warnings    = $script:Warnings
        }

        # ---- Drift detection ----
        # Note: the drift snapshot is always keyed on the REAL tenant ID ($ctx.TenantId), even under
        # -Redact, so run-over-run comparison keeps working correctly. This file is written locally to
        # OutputPath\.trc-history and is never included in the HTML/MD/PDF report itself.
        Write-Section 'Comparing against last run for this tenant'
        $snapshotPath = Get-DriftSnapshotPath -OutputPath $OutputPath -TenantId $ctx.TenantId
        $currentSnapshot = Get-CurrentMetricsSnapshot -Data $script:Report
        if (Test-Path $snapshotPath) {
            try {
                $previousSnapshot = Get-Content -Path $snapshotPath -Raw | ConvertFrom-Json -ErrorAction Stop
                $script:Report.Drift = Get-DriftComparison -Previous $previousSnapshot -Current $currentSnapshot
                Write-Step "Found a prior run from $($previousSnapshot.CapturedAt) - $($script:Report.Drift.Changes.Count) metric(s) changed."
            }
            catch {
                Add-ReportWarning -Section 'Drift' -Message "Could not read prior run snapshot: $($_.Exception.Message)"
            }
        }
        else {
            Write-Step 'No prior run found for this tenant - this run establishes the baseline.'
        }
        try {
            $currentSnapshot | ConvertTo-Json | Set-Content -Path $snapshotPath -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Add-ReportWarning -Section 'Drift' -Message "Could not save run snapshot for future comparison: $($_.Exception.Message)"
        }

        # ---- Render & Export ----
        Write-Section 'Rendering report'

        $stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
        # When -Redact is set, TenantInfo.DefaultDomain is already a redacted placeholder (see
        # Get-TenantInfoData), so this naturally produces a redacted folder name too - no separate
        # branch needed here.
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

        return [PSCustomObject]@{
            OutputFolder = $outDir
            HtmlPath     = $htmlPath
            MarkdownPath = $mdPath
            PdfPath      = if (Test-Path $pdfPath) { $pdfPath } else { $null }
            WarningCount = $script:Warnings.Count
            Report       = $script:Report
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
}

#endregion Orchestration

Export-ModuleMember -Function *
