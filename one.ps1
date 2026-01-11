# one.ps1
# Win11: переключение дефолтов через DefaultAppAssociations XML + HKLM Policy (admin)
# Меню 1/2/3: 7-Zip / Adobe Reader / Yandex Browser
# Поиск Capabilities: RegisteredApplications (HKLM/HKCU) + Classes\Applications\<exe>\Capabilities
# Fallback: SupportedTypes -> ProgId = Applications\<exe>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-AdminOrDie {
    if (-not (Test-IsAdmin)) {
        Write-Host "Нужны права администратора. Запусти CMD/PowerShell от имени администратора." -ForegroundColor Red
        throw "Not admin"
    }
}

function Open-BaseKey {
    param([Microsoft.Win32.RegistryHive]$Hive, [Microsoft.Win32.RegistryView]$View)
    [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $View)
}

function Test-RegKeyExists {
    param([Microsoft.Win32.RegistryHive]$Hive, [Microsoft.Win32.RegistryView]$View, [string]$SubKeyPath)
    $base = Open-BaseKey -Hive $Hive -View $View
    try {
        $key = $base.OpenSubKey($SubKeyPath)
        if ($key) { $key.Close(); return $true }
        return $false
    } finally { $base.Close() }
}

function Get-RegValueMap {
    param([Microsoft.Win32.RegistryHive]$Hive, [Microsoft.Win32.RegistryView]$View, [string]$SubKeyPath)
    $base = Open-BaseKey -Hive $Hive -View $View
    try {
        $key = $base.OpenSubKey($SubKeyPath)
        if (-not $key) { return @{} }
        try {
            $map = @{}
            foreach ($name in $key.GetValueNames()) {
                $map[$name] = [string]$key.GetValue($name)
            }
            return $map
        } finally { $key.Close() }
    } finally { $base.Close() }
}

function Get-RegValue {
    param([Microsoft.Win32.RegistryHive]$Hive, [Microsoft.Win32.RegistryView]$View, [string]$SubKeyPath, [string]$ValueName)
    $base = Open-BaseKey -Hive $Hive -View $View
    try {
        $key = $base.OpenSubKey($SubKeyPath)
        if (-not $key) { return $null }
        try { return $key.GetValue($ValueName) }
        finally { $key.Close() }
    } finally { $base.Close() }
}

function Find-CapabilitiesByRegisteredApplicationsRegex {
    param([string]$NameRegex)

    $targets = @(
        @{ Hive = [Microsoft.Win32.RegistryHive]::LocalMachine;  Views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32) },
        @{ Hive = [Microsoft.Win32.RegistryHive]::CurrentUser;   Views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32) }
    )

    foreach ($t in $targets) {
        foreach ($view in $t.Views) {
            $map = Get-RegValueMap -Hive $t.Hive -View $view -SubKeyPath 'SOFTWARE\RegisteredApplications'
            foreach ($k in $map.Keys) {
                if ($k -match $NameRegex) {
                    return @{ Hive = $t.Hive; View = $view; CapPath = $map[$k] } # путь относительно Hive
                }
            }
        }
    }
    return $null
}

function Find-CapabilitiesInClassesApplicationsRegex {
    param([string]$NameRegex)

    # Ищем в HKLM\SOFTWARE\Classes\Applications\<exe>\Capabilities
    $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
    $appsRoot = 'SOFTWARE\Classes\Applications'

    foreach ($view in $views) {
        $base = Open-BaseKey -Hive $hive -View $view
        try {
            $root = $base.OpenSubKey($appsRoot)
            if (-not $root) { continue }
            try {
                foreach ($sub in $root.GetSubKeyNames()) {
                    $cap = "$appsRoot\$sub\Capabilities"
                    if (-not (Test-RegKeyExists -Hive $hive -View $view -SubKeyPath $cap)) { continue }

                    $appName = Get-RegValue -Hive $hive -View $view -SubKeyPath $cap -ValueName "ApplicationName"
                    $locStr  = Get-RegValue -Hive $hive -View $view -SubKeyPath $cap -ValueName "LocalizedString"
                    $hay = "$sub $appName $locStr"
                    if ($hay -match $NameRegex) {
                        return @{ Hive = $hive; View = $view; CapPath = $cap }
                    }
                }
            } finally { $root.Close() }
        } finally { $base.Close() }
    }

    return $null
}

function Read-CapabilitiesAssociations {
    param(
        [Microsoft.Win32.RegistryHive]$Hive,
        [Microsoft.Win32.RegistryView]$View,
        [string]$CapabilitiesPath,
        [ValidateSet('FileAssociations','URLAssociations')] [string]$Type
    )

    if ([string]::IsNullOrWhiteSpace($CapabilitiesPath)) { return @{} }
    $sub = "$CapabilitiesPath\$Type"
    if (-not (Test-RegKeyExists -Hive $Hive -View $View -SubKeyPath $sub)) { return @{} }
    Get-RegValueMap -Hive $Hive -View $View -SubKeyPath $sub
}

function Get-CapabilitiesAppName {
    param([Microsoft.Win32.RegistryHive]$Hive, [Microsoft.Win32.RegistryView]$View, [string]$CapabilitiesPath)

    $name = Get-RegValue -Hive $Hive -View $View -SubKeyPath $CapabilitiesPath -ValueName "ApplicationName"
    if ($name) { return [string]$name }

    $loc = Get-RegValue -Hive $Hive -View $View -SubKeyPath $CapabilitiesPath -ValueName "LocalizedString"
    if ($loc) { return [string]$loc }

    return "Custom App"
}

function Get-AppNameFromApplicationsKey {
    param([string]$ExeName)

    $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
    $k = "SOFTWARE\Classes\Applications\$ExeName"

    foreach ($view in $views) {
        $friendly = Get-RegValue -Hive $hive -View $view -SubKeyPath $k -ValueName "FriendlyAppName"
        if ($friendly) { return [string]$friendly }

        $appName = Get-RegValue -Hive $hive -View $view -SubKeyPath $k -ValueName "ApplicationName"
        if ($appName) { return [string]$appName }
    }
    return $ExeName
}

function Get-AssociationsFromSupportedTypes {
    param(
        [string]$ExeName
    )

    # HKLM\SOFTWARE\Classes\Applications\<exe>\SupportedTypes
    $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
    $key = "SOFTWARE\Classes\Applications\$ExeName\SupportedTypes"

    foreach ($view in $views) {
        if (Test-RegKeyExists -Hive $hive -View $view -SubKeyPath $key) {
            $vals = Get-RegValueMap -Hive $hive -View $view -SubKeyPath $key
            if ($vals.Count -gt 0) {
                $map = @{}
                foreach ($ext in $vals.Keys) {
                    # ProgId = Applications\<exe>
                    $e = $ext
                    if (-not $e.StartsWith(".")) { $e = ".$e" }
                    $map[$e] = "Applications\$ExeName"
                }
                return $map
            }
        }
    }

    return @{}
}

function Write-DefaultAssociationsXml {
    param([string]$OutPath, [hashtable]$Associations, [string]$ApplicationName)

    $dir = Split-Path -Parent $OutPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$sb.AppendLine('<DefaultAssociations>')

    foreach ($id in ($Associations.Keys | Sort-Object)) {
        $progId = $Associations[$id]
        if ([string]::IsNullOrWhiteSpace($progId)) { continue }

        $safeApp = [Security.SecurityElement]::Escape($ApplicationName)
        $safeId  = [Security.SecurityElement]::Escape($id)
        $safePid = [Security.SecurityElement]::Escape($progId)

        [void]$sb.AppendLine("  <Association Identifier=`"$safeId`" ProgId=`"$safePid`" ApplicationName=`"$safeApp`" />")
    }

    [void]$sb.AppendLine('</DefaultAssociations>')
    $sb.ToString() | Set-Content -Path $OutPath -Encoding UTF8
}

function Set-DefaultAssociationsPolicy {
    param([string]$XmlPath)

    $policyKey = 'HKLM:\Software\Policies\Microsoft\Windows\System'
    if (-not (Test-Path $policyKey)) { New-Item -Path $policyKey -Force | Out-Null }
    New-ItemProperty -Path $policyKey -Name 'DefaultAssociationsConfiguration' -Value $XmlPath -PropertyType String -Force | Out-Null
}

function Clear-UserChoice {
    param([string[]]$FileExts, [string[]]$UrlProtocols)

    foreach ($ext in $FileExts | Sort-Object -Unique) {
        $e = $ext
        if (-not $e.StartsWith(".")) { $e = ".$e" }
        $p = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$e\UserChoice"
        if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue }
    }

    foreach ($proto in $UrlProtocols | Sort-Object -Unique) {
        $p = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$proto\UserChoice"
        if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Restart-Explorer {
    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Process explorer.exe | Out-Null
}

function Try-GpUpdate {
    try { Start-Process gpupdate.exe -ArgumentList "/target:computer","/force" -Wait -NoNewWindow | Out-Null } catch { }
}

function Apply-DefaultPolicyFromMap {
    param(
        [string]$Title,
        [string]$XmlName,
        [hashtable]$AssocMap,
        [string]$AppName,
        [string[]]$UrlProtocols = @()
    )

    if (-not $AssocMap -or $AssocMap.Count -eq 0) {
        throw "$Title: нет найденных ассоциаций."
    }

    $xml = "C:\ProgramData\DefaultAppAssoc\$XmlName"
    Write-DefaultAssociationsXml -OutPath $xml -Associations $AssocMap -ApplicationName $AppName
    Set-DefaultAssociationsPolicy -XmlPath $xml

    Clear-UserChoice -FileExts $AssocMap.Keys -UrlProtocols $UrlProtocols
    Try-GpUpdate
    Restart-Explorer

    Write-Host "Готово: $Title" -ForegroundColor Green
    Write-Host "Ассоциаций записано: $($AssocMap.Count)" -ForegroundColor Green
    Write-Host "XML: $xml" -ForegroundColor DarkGray
}

function Apply-7Zip {
    Ensure-AdminOrDie

    $title = "7-Zip"
    $regex = '(?i)7-zip|7zip'
    $xmlName = "defaults-7zip.xml"

    $hit = Find-CapabilitiesByRegisteredApplicationsRegex -NameRegex $regex
    if (-not $hit) { $hit = Find-CapabilitiesInClassesApplicationsRegex -NameRegex $regex }

    $fileAssocs = @{}
    $appName = $null

    if ($hit) {
        $appName = Get-CapabilitiesAppName -Hive $hit.Hive -View $hit.View -CapabilitiesPath $hit.CapPath
        $fileAssocs = Read-CapabilitiesAssociations -Hive $hit.Hive -View $hit.View -CapabilitiesPath $hit.CapPath -Type FileAssociations
    }

    if (-not $fileAssocs -or $fileAssocs.Count -eq 0) {
        # fallback: Applications\7zFM.exe\SupportedTypes
        $exe = "7zFM.exe"
        $fileAssocs = Get-AssociationsFromSupportedTypes -ExeName $exe
        $appName = Get-AppNameFromApplicationsKey -ExeName $exe
    }

    if (-not $fileAssocs -or $fileAssocs.Count -eq 0) {
        throw "7-Zip не зарегистрировал Capabilities/SupportedTypes. Если 7-Zip установлен, открой 7-Zip File Manager → Tools → Options → System и включи ассоциации, либо переустанови обычную (не portable) версию."
    }

    Apply-DefaultPolicyFromMap -Title $title -XmlName $xmlName -AssocMap $fileAssocs -AppName $appName
}

function Apply-Adobe {
    Ensure-AdminOrDie

    $title = "Adobe Reader/Acrobat"
    $regex = '(?i)acrobat|adobe.*reader|reader.*dc|adobe.*acrobat'
    $xmlName = "defaults-adobe.xml"

    $hit = Find-CapabilitiesByRegisteredApplicationsRegex -NameRegex $regex
    if (-not $hit) { $hit = Find-CapabilitiesInClassesApplicationsRegex -NameRegex $regex }

    $fileAssocs = @{}
    $appName = $null

    if ($hit) {
        $appName = Get-CapabilitiesAppName -Hive $hit.Hive -View $hit.View -CapabilitiesPath $hit.CapPath
        $fileAssocs = Read-CapabilitiesAssociations -Hive $hit.Hive -View $hit.View -CapabilitiesPath $hit.CapPath -Type FileAssociations
    }

    if (-not $fileAssocs -or $fileAssocs.Count -eq 0) {
        # fallback: Applications\AcroRd32.exe\SupportedTypes
        $exe = "AcroRd32.exe"
        $fileAssocs = Get-AssociationsFromSupportedTypes -ExeName $exe
        $appName = Get-AppNameFromApplicationsKey -ExeName $exe
    }

    if (-not $fileAssocs -or $fileAssocs.Count -eq 0) {
        throw "Adobe Reader/Acrobat не зарегистрировал Capabilities/SupportedTypes (или не установлен)."
    }

    Apply-DefaultPolicyFromMap -Title $title -XmlName $xmlName -AssocMap $fileAssocs -AppName $appName
}

function Find-YandexBrowserCapabilities {
    # HKLM\SOFTWARE\Clients\StartMenuInternet\<browser>\Capabilities
    $basePath = 'SOFTWARE\Clients\StartMenuInternet'
    $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
    $hive = [Microsoft.Win32.RegistryHive]::LocalMachine

    foreach ($view in $views) {
        $base = Open-BaseKey -Hive $hive -View $view
        try {
            $root = $base.OpenSubKey($basePath)
            if (-not $root) { continue }
            try {
                foreach ($sub in $root.GetSubKeyNames()) {
                    $cap = "$basePath\$sub\Capabilities"
                    if (-not (Test-RegKeyExists -Hive $hive -View $view -SubKeyPath $cap)) { continue }

                    $appName = Get-RegValue -Hive $hive -View $view -SubKeyPath $cap -ValueName "ApplicationName"
                    $candidate = ($sub + " " + $appName)
                    if ($candidate -match '(?i)yandex') {
                        return @{ Hive = $hive; View = $view; CapPath = $cap; ClientKey = $sub }
                    }
                }
            } finally { $root.Close() }
        } finally { $base.Close() }
    }

    return $null
}

function Apply-Yandex {
    Ensure-AdminOrDie

    $hit = Find-YandexBrowserCapabilities
    if (-not $hit) { throw "Не найден Yandex Browser в HKLM:\SOFTWARE\Clients\StartMenuInternet (не установлен/не зарегистрирован как браузер)." }

    $appName = Get-CapabilitiesAppName -Hive $hit.Hive -View $hit.View -CapabilitiesPath $hit.CapPath

    $fileAssocs = Read-CapabilitiesAssociations -Hive $hit.Hive -View $hit.View -CapabilitiesPath $hit.CapPath -Type FileAssociations
    $urlAssocs  = Read-CapabilitiesAssociations -Hive $hit.Hive -View $hit.View -CapabilitiesPath $hit.CapPath -Type URLAssociations

    if (($fileAssocs.Count -eq 0) -and ($urlAssocs.Count -eq 0)) {
        throw "У Yandex Browser не найдено Capabilities\FileAssociations/URLAssociations."
    }

    $merged = @{}
    foreach ($k in $fileAssocs.Keys) { $merged[$k] = $fileAssocs[$k] }
    foreach ($k in $urlAssocs.Keys)  { $merged[$k] = $urlAssocs[$k] }

    Apply-DefaultPolicyFromMap -Title "Yandex Browser" -XmlName "defaults-yandex.xml" -AssocMap $merged -AppName $appName -UrlProtocols $urlAssocs.Keys
}

function Offer-Logoff {
    Write-Host ""
    Write-Host "ВАЖНО: дефолты в Windows 11 надёжно применяются при следующем входе в систему." -ForegroundColor Yellow
    $ans = Read-Host "Сделать выход из системы сейчас? (y/n)"
    if ($ans -match '^(?i)y$') { shutdown /l }
}

# ---- MAIN LOOP ----
while ($true) {
    try {
        Write-Host ""
        Write-Host "Выбор:" -ForegroundColor Cyan
        Write-Host "  1) Ассоциации -> 7-Zip"
        Write-Host "  2) Ассоциации -> Adobe Reader/Acrobat"
        Write-Host "  3) Ассоциации -> Yandex Browser (включая http/https)"
        Write-Host "  0) Выход"
        Write-Host ""

        $choice = Read-Host "Введи 0, 1, 2 или 3"

        switch ($choice) {
            "1" { Apply-7Zip;  Offer-Logoff }
            "2" { Apply-Adobe; Offer-Logoff }
            "3" { Apply-Yandex; Offer-Logoff }
            "0" { break }
            default { Write-Host "Неверный выбор." -ForegroundColor Red }
        }
    }
    catch {
        Write-Host "Ошибка: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Вернулся в меню." -ForegroundColor DarkGray
    }
}
