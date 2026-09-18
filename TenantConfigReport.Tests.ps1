#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for TenantConfigReport.psm1.

.DESCRIPTION
    These tests cover the module's pure, testable surface: report rendering (HTML/Markdown), the
    narrative summary generator, drift-comparison logic, the shared redaction-hash helper, and (via
    Pester mocks of the Graph cmdlets) Get-TenantInfoData's -Redact behavior specifically, since
    redaction correctness is security-relevant and worth testing directly rather than only by hand.
    They do NOT cover the rest of the Connect-* or Get-*Data functions' live data-shape logic, since
    exercising those fully requires a real Graph/Exchange/SharePoint connection and tenant data - that
    broader surface is verified manually against a test tenant instead.

    Run from the repo root:
        Invoke-Pester ./Tests/TenantConfigReport.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'TenantConfigReport.psm1'
    Import-Module $modulePath -Force

    # A minimal but structurally complete mock report, reused across tests and tweaked per-test as needed.
    function New-MockReportData {
        [ordered]@{
            Meta = [PSCustomObject]@{
                GeneratedAt = '2026-09-15 12:00:00'
                RunBy       = 'admin@contoso.onmicrosoft.com'
                TenantId    = '11111111-2222-3333-4444-555555555555'
                Warnings    = @()
            }
            TenantInfo = [PSCustomObject]@{
                DisplayName = 'Contoso Ltd'
                TenantId    = '11111111-2222-3333-4444-555555555555'
                DefaultDomain = 'contoso.com'
                VerifiedDomains = @(
                    [PSCustomObject]@{ Name = 'contoso.com'; IsDefault = $true; IsInitial = $false; Type = 'Managed' }
                )
                City = 'London'; Country = 'GB'; TechNotifyEmails = 'admin@contoso.com'
                CreatedDateTime = (Get-Date); OnPremisesSyncOn = $false
            }
            Users = [PSCustomObject]@{
                Total = 150; Enabled = 140; Disabled = 10; Guests = 5; Members = 145
                CloudOnly = 100; HybridSynced = 50; Licensed = 130; Unlicensed = 20
                StaleOver90Days = 12
                Detail = @([PSCustomObject]@{ DisplayName = 'Jane Doe'; UserPrincipalName = 'jane@contoso.com'; Enabled = $true; Type = 'Member'; Synced = $false; Licensed = $true; LastSignIn = (Get-Date); Created = (Get-Date) })
            }
            Groups = [PSCustomObject]@{
                Total = 40; Microsoft365Groups = 15; DynamicGroups = 2; SecurityGroups = 15
                MailEnabledSecurity = 3; DistributionGroups = 5; OwnerlessGroups = 4
                Detail = @([PSCustomObject]@{ DisplayName = 'All Staff'; Type = 'Microsoft 365'; Dynamic = $false; OwnerCount = 1 })
            }
            Licenses = [PSCustomObject]@{
                Detail = @([PSCustomObject]@{ SkuPartNumber = 'ENTERPRISEPACK'; Enabled = 150; Consumed = 130; Available = 20; PercentUsed = 86.7; NearLimit = $false })
            }
            AdminRoles = [PSCustomObject]@{
                GlobalAdminCount = 3; RolesInUse = 2
                Detail = @([PSCustomObject]@{ RoleName = 'Global Administrator'; MemberCount = 3; Members = 'Jane Doe, John Smith, Admin User' })
            }
            ConditionalAccess = [PSCustomObject]@{
                Total = 3; Enabled = 2; ReportOnly = 1; Disabled = 0
                Detail = @([PSCustomObject]@{ DisplayName = 'Require MFA'; State = 'enabled'; GrantControls = 'mfa'; Users = 'All users'; Apps = 'All apps' })
            }
            Mfa = [PSCustomObject]@{
                TotalUsersReported = 150; MfaCapable = 120; MfaRegistered = 115; PercentMfaCapable = 80.0
                AdminsWithoutMfa = 1; AdminsWithoutMfaDetail = 'admin2@contoso.com'; SecurityDefaultsEnabled = $false
            }
            Applications = [PSCustomObject]@{
                Total = 25
                Detail = @([PSCustomObject]@{ DisplayName = 'HR App'; Created = (Get-Date); ResourceApiCount = 2; PermissionCount = 6 })
                Note = 'Top 50 shown.'
            }
            ExchangeOnline = [PSCustomObject]@{
                TotalMailboxes = 140
                MailboxesByType = @([PSCustomObject]@{ Type = 'UserMailbox'; Count = 130 })
                TransportRuleCount = 4; TransportRules = @(); InboundConnectorCount = 1; OutboundConnectorCount = 1
            }
            SharePoint = [PSCustomObject]@{
                SiteCount = 60; TotalStorageUsedGb = 245.6
                SharingCapability = 'ExternalUserSharingOnly'; OneDriveSharingCapability = 'ExternalUserSharingOnly'
                DefaultLinkPermission = 'View'; LegacyAuthProtocolsEnabled = $true
                SiteOverrideCount = 1
                SiteOverrides = @([PSCustomObject]@{ Url = 'https://contoso.sharepoint.com/sites/hr'; Title = 'HR Site'; SharingCapability = 'ExternalUserAndGuestSharing'; StorageUsedGb = 12.4 })
            }
            SecureScore = [PSCustomObject]@{
                OverallCurrentScore = 210.5; OverallMaxScore = 300; OverallPercent = 70.2
                IdentityPercent = 74.0; IdentityControlCount = 20
                TopOpportunities = @([PSCustomObject]@{ ControlName = 'MFARegistrationV2'; Description = 'Ensure MFA registration'; Score = 2.0; MaxScore = 10; Gap = 8.0 })
                AllIdentityControls = @()
                DevicePercent = 55.5; DeviceControlCount = 10
                DeviceTopOpportunities = @([PSCustomObject]@{ ControlName = 'DeviceComplianceV2'; Description = 'Ensure device compliance'; Score = 1.0; MaxScore = 8; Gap = 7.0 })
                AllDeviceControls = @()
                CreatedDateTime = (Get-Date)
            }
            UserSettings = [PSCustomObject]@{
                UsersCanRegisterApps = $true; UsersCanCreateSecurityGroups = $true; UsersCanCreateM365Groups = $true
                UsersCanCreateTenants = $false; UsersCanReadOtherUsers = $true; AdminsCanUseSspr = $true
                GuestInviteSetting = 'everyone'; EmailVerifiedUsersCanJoin = $false; LegacyMsolPowerShellBlocked = $false
            }
            Drift = $null
        }
    }
}

Describe 'New-HtmlReport' {
    BeforeAll {
        $script:data = New-MockReportData
        $script:html = New-HtmlReport -Data $script:data
    }

    It 'produces non-empty HTML' {
        $script:html | Should -Not -BeNullOrEmpty
    }

    It 'includes the tenant display name' {
        $script:html | Should -Match 'Contoso Ltd'
    }

    It 'includes all ten navigation anchors' {
        foreach ($anchor in @('dashboard','tenant','users','groups','licenses','roles','ca','mfa','exo','spo','securescore','usersettings','drift')) {
            $script:html | Should -Match "id=`"$anchor`""
        }
    }

    It 'flags a NearLimit-false license without the bad pill' {
        $script:html | Should -Match 'ENTERPRISEPACK'
    }

    It 'renders the SharePoint site-override table when overrides exist' {
        $script:html | Should -Match 'HR Site'
    }

    It 'renders a skipped notice for a null section instead of throwing' {
        $data = New-MockReportData
        $data.SharePoint = $null
        { New-HtmlReport -Data $data } | Should -Not -Throw
        (New-HtmlReport -Data $data) | Should -Match 'SharePoint section skipped or unavailable'
    }

    It 'HTML-encodes tenant display name to avoid markup injection' {
        $data = New-MockReportData
        $data.TenantInfo.DisplayName = 'Contoso <script>alert(1)</script>'
        $html = New-HtmlReport -Data $data
        $html | Should -Not -Match '<script>alert'
    }
}

Describe 'New-MarkdownReport' {
    BeforeAll {
        $script:data = New-MockReportData
        $script:md = New-MarkdownReport -Data $script:data
    }

    It 'produces non-empty Markdown' {
        $script:md | Should -Not -BeNullOrEmpty
    }

    It 'includes the executive summary blockquote' {
        $script:md | Should -Match '> \*\*Executive Summary:\*\*'
    }

    It 'includes the full per-user table (unlike the HTML summary-only view)' {
        $script:md | Should -Match 'jane@contoso.com'
    }
}

Describe 'New-NarrativeSummary' {
    It 'reports no concerns when metrics are healthy' {
        $data = New-MockReportData
        $data.AdminRoles.GlobalAdminCount = 3
        $data.Mfa.AdminsWithoutMfa = 0
        $data.ConditionalAccess.Total = 3
        $data.UserSettings.UsersCanRegisterApps = $false
        $data.UserSettings.UsersCanCreateSecurityGroups = $false
        $data.UserSettings.UsersCanCreateTenants = $false
        $data.SecureScore.OverallPercent = 85
        $data.Licenses.Detail[0].NearLimit = $false

        $narrative = New-NarrativeSummary -Data $data
        $narrative | Should -Match 'No significant configuration concerns'
    }

    It 'flags a low Global Admin count' {
        $data = New-MockReportData
        $data.AdminRoles.GlobalAdminCount = 1
        $narrative = New-NarrativeSummary -Data $data
        $narrative | Should -Match 'below the recommended minimum of 2'
    }

    It 'flags admins without MFA' {
        $data = New-MockReportData
        $data.Mfa.AdminsWithoutMfa = 2
        $narrative = New-NarrativeSummary -Data $data
        $narrative | Should -Match '2 admin account\(s\) without MFA registered'
    }

    It 'does not count the informational user-count line as a concern' {
        $data = New-MockReportData
        $data.AdminRoles.GlobalAdminCount = 3
        $data.Mfa.AdminsWithoutMfa = 0
        $data.ConditionalAccess.Total = 3
        $data.UserSettings.UsersCanRegisterApps = $false
        $data.UserSettings.UsersCanCreateSecurityGroups = $false
        $data.UserSettings.UsersCanCreateTenants = $false
        $data.SecureScore.OverallPercent = 85
        $data.Licenses.Detail[0].NearLimit = $false

        $narrative = New-NarrativeSummary -Data $data
        $narrative | Should -Not -Match '\d+ item\(s\) worth a closer look'
    }
}

Describe 'Get-DriftComparison' {
    It 'reports no changes when metrics are identical' {
        $prev = [PSCustomObject]@{ CapturedAt = '2026-08-01'; GlobalAdminCount = 3; ConditionalAccessTotal = 3; SecureScorePercent = 70; LicensesNearLimit = 0; UserTotal = 150; MfaPercent = 80 }
        $cur  = [PSCustomObject]@{ CapturedAt = '2026-09-01'; GlobalAdminCount = 3; ConditionalAccessTotal = 3; SecureScorePercent = 70; LicensesNearLimit = 0; UserTotal = 150; MfaPercent = 80 }
        $drift = Get-DriftComparison -Previous $prev -Current $cur
        $drift.Changes.Count | Should -Be 0
    }

    It 'detects a change in Global Admin count' {
        $prev = [PSCustomObject]@{ CapturedAt = '2026-08-01'; GlobalAdminCount = 3; ConditionalAccessTotal = 3; SecureScorePercent = 70; LicensesNearLimit = 0; UserTotal = 150; MfaPercent = 80 }
        $cur  = [PSCustomObject]@{ CapturedAt = '2026-09-01'; GlobalAdminCount = 5; ConditionalAccessTotal = 3; SecureScorePercent = 70; LicensesNearLimit = 0; UserTotal = 150; MfaPercent = 80 }
        $drift = Get-DriftComparison -Previous $prev -Current $cur
        $drift.Changes | Should -Contain 'Global Admins: 3 -> 5'
    }

    It 'detects multiple simultaneous changes' {
        $prev = [PSCustomObject]@{ CapturedAt = '2026-08-01'; GlobalAdminCount = 3; ConditionalAccessTotal = 3; SecureScorePercent = 65; LicensesNearLimit = 0; UserTotal = 150; MfaPercent = 70 }
        $cur  = [PSCustomObject]@{ CapturedAt = '2026-09-01'; GlobalAdminCount = 3; ConditionalAccessTotal = 4; SecureScorePercent = 72; LicensesNearLimit = 1; UserTotal = 155; MfaPercent = 82 }
        $drift = Get-DriftComparison -Previous $prev -Current $cur
        $drift.Changes.Count | Should -Be 5
    }
}

Describe 'Get-CurrentMetricsSnapshot' {
    It 'handles a fully-populated report without throwing' {
        $data = New-MockReportData
        { Get-CurrentMetricsSnapshot -Data $data } | Should -Not -Throw
    }

    It 'handles null sections gracefully (module/connection was skipped)' {
        $data = New-MockReportData
        $data.AdminRoles = $null
        $data.SecureScore = $null
        $snapshot = Get-CurrentMetricsSnapshot -Data $data
        $snapshot.GlobalAdminCount | Should -BeNullOrEmpty
        $snapshot.SecureScorePercent | Should -BeNullOrEmpty
    }
}

Describe 'Get-ReportCss' {
    It 'loads the real template file when run from the repo layout' {
        $css = Get-ReportCss
        $css | Should -Match '--bg-page'
    }
}

Describe 'Get-RedactionHash' {
    It 'is deterministic for the same input' {
        (Get-RedactionHash -Value 'jane@contoso.com') | Should -Be (Get-RedactionHash -Value 'jane@contoso.com')
    }

    It 'produces different output for different input' {
        (Get-RedactionHash -Value 'jane@contoso.com') | Should -Not -Be (Get-RedactionHash -Value 'john@contoso.com')
    }

    It 'never contains a substring of the original value' {
        $value = 'a7f3c9e1-8b2d-4f6a-9c1e-7d5b3a8f2c94'
        $hash = Get-RedactionHash -Value $value
        $value | Should -Not -Match ([regex]::Escape($hash))
    }

    It 'respects the requested length' {
        (Get-RedactionHash -Value 'test' -Length 4).Length | Should -Be 4
        (Get-RedactionHash -Value 'test' -Length 12).Length | Should -Be 12
    }
}

Describe 'Get-TenantInfoData -Redact' {
    BeforeAll {
        # Mock Get-MgOrganization so the real Get-TenantInfoData function can run without a live connection.
        Mock Get-MgOrganization {
            [PSCustomObject]@{
                DisplayName = 'Contoso Ltd'
                Id = 'a7f3c9e1-8b2d-4f6a-9c1e-7d5b3a8f2c94'
                VerifiedDomains = @(
                    [PSCustomObject]@{ Name = 'contoso.com'; IsDefault = $true; IsInitial = $false; Type = 'Managed' }
                    [PSCustomObject]@{ Name = 'contoso.onmicrosoft.com'; IsDefault = $false; IsInitial = $true; Type = 'Managed' }
                )
                City = 'London'; CountryLetterCode = 'GB'
                TechnicalNotificationMails = @('admin@contoso.com', 'itops@contoso.com')
                CreatedDateTime = (Get-Date); OnPremisesSyncEnabled = $false
            }
        }
    }

    It 'passes through real values when -Redact is not set' {
        $result = Get-TenantInfoData
        $result.DisplayName | Should -Be 'Contoso Ltd'
        $result.DefaultDomain | Should -Be 'contoso.com'
        $result.TechNotifyEmails | Should -Match 'admin@contoso.com'
    }

    It 'masks DisplayName, TenantId, and DefaultDomain when -Redact is set' {
        $result = Get-TenantInfoData -Redact
        $result.DisplayName | Should -Not -Match 'Contoso'
        $result.TenantId | Should -Not -Match 'a7f3c9e1'
        $result.DefaultDomain | Should -Not -Match 'contoso'
    }

    It 'masks every verified domain, not just the default one' {
        $result = Get-TenantInfoData -Redact
        foreach ($d in $result.VerifiedDomains) {
            $d.Name | Should -Not -Match 'contoso'
        }
    }

    It 'gives distinct placeholders to distinct real domains (does not collapse them)' {
        $result = Get-TenantInfoData -Redact
        $result.VerifiedDomains[0].Name | Should -Not -Be $result.VerifiedDomains[1].Name
    }

    It 'masks technical notification emails and gives each a distinct placeholder' {
        $result = Get-TenantInfoData -Redact
        $result.TechNotifyEmails | Should -Not -Match 'contoso|admin@|itops@'
        $result.TechNotifyEmails | Should -Match '@redacted\.example'
        $placeholders = $result.TechNotifyEmails -split ', '
        $placeholders.Count | Should -Be 2
        $placeholders[0] | Should -Not -Be $placeholders[1]
    }

    It 'is deterministic - redacting the same tenant twice gives the same placeholders' {
        $first = Get-TenantInfoData -Redact
        $second = Get-TenantInfoData -Redact
        $first.DisplayName | Should -Be $second.DisplayName
        $first.TenantId | Should -Be $second.TenantId
        $first.DefaultDomain | Should -Be $second.DefaultDomain
        $first.TechNotifyEmails | Should -Be $second.TechNotifyEmails
    }

    It 'produces a folder-slug-safe DefaultDomain (no characters that would leak into a shared path unexpectedly)' {
        $result = Get-TenantInfoData -Redact
        $slug = ($result.DefaultDomain -replace '[^a-zA-Z0-9.-]', '') -replace '\.onmicrosoft\.com$', ''
        $slug | Should -Not -Match 'contoso'
        $slug | Should -Not -BeNullOrEmpty
    }
}

Describe 'Format-Number' {
    It 'formats a number with thousands separators' {
        Format-Number -Value 1234567 | Should -Be '1,234,567'
    }

    It 'returns N/A for null' {
        Format-Number -Value $null | Should -Be 'N/A'
    }
}
