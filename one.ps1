# one.ps1
# Win11: переключение дефолтов через DefaultAppAssociations XML + HKLM Policy
# 1) 7-Zip (все расширения из Capabilities\FileAssociations)
# 2) Adobe Reader/Acrobat (все расширения из Capabilities\FileAssociations)
# 3) Yandex Browser (протоколы + web-расширения из Capabilities\URLAssociations/FileAssociations)
#
# ВАЖНО: применение дефолтов по поддерживаемому механизму происходит на входе в систему.
# Скрипт делает максимум "сразу": ставит политику, чистит UserChoice, перезапускает Explorer.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-AdminOrDie {
    if (-not (Test-IsAdmin)) {
        Write-Host "Нужны права администратора. Запусти CMD от имени администратора." -ForegroundColor Red
        exit 1
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

function Find-CapabilitiesPathByRegisteredAppNameRegex {
    param([string]$NameRegex)

    $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
    foreach ($view in $views) {
        $regApps = Get-RegValueMap -Hive LocalMachine -View $view -SubKeyPath 'SOFTWARE\RegisteredApplications'
        foreach ($k in $regApps.Keys) {
            if ($k -match $NameRegex) {
                return @{ View = $view; CapPath = $regApps[$k] } # e.g. SOFTWARE\7-Zip\Capabilities
            }
        }
    }
    return $null
}

function Read-CapabilitiesAssociations {
    param(
        [Microsoft.Win32.RegistryView]$View,
        [string]$CapabilitiesPath,
        [ValidateSet('FileAssociations','URLAssociations')] [string]$Type
    )

    if ([string]::IsNullOrWhiteSpace($CapabilitiesPath)) { return @{} }
    $sub = "$CapabilitiesPath\$Type"
    if (-not (Test-RegKeyExists -Hive LocalMachine -View $View -SubKeyPath $sub)) { return @{} }
    Get-RegValueMap -Hive LocalMachine -View $View -SubKeyPath $sub
}

function Get-CapabilitiesAppName {
    param([Microsoft.Win32.RegistryView]$View, [string]$CapabilitiesPath)

    $name = Get-RegValue -Hive LocalMachine -View $View -SubKeyPath $CapabilitiesPath -ValueName "ApplicationName"
    if ($name) { return [string]$name }

    $loc = Get-RegValue -Hive LocalMachine -View $View -SubKeyPath $CapabilitiesPath -ValueName "LocalizedString"
    if ($loc) { return [string]$loc }

    return "Custom App"
}

function Find-YandexBrowserCapabilities {
    $basePath = 'SOFTWARE\Clients\StartMenuInternet'
    $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)

    foreach ($view in $views) {
        $base = Open-BaseKey -Hive LocalMachine -View $view
        try {
            $root = $base.OpenSubKey($basePath)
            if (-not $root) { continue }
            try {
                foreach ($sub in $root.GetSubKeyNames()) {
                    $cap = "$basePath\$sub\Capabilities"
                    if (-not (Test-RegKeyExists -Hive LocalMachine -View $view -SubKeyPath $cap)) { continue }

                    $appName = Get-RegValue -Hive LocalMachine -View $view -SubKeyPath $cap -ValueName "ApplicationName"
                    $candidate = ($sub + " " + $appName)
                    if ($candidate -match '(?i)yandex') {
                        return @{ View = $view; CapPath = $cap; ClientKey = $sub }
                    }
                }
            } finally { $root.Close() }
        } finally { $base.Close() }
    }
    return $null
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
    try {
        Start-Process -FilePath "gpupdate.exe" -ArgumentList "/target:computer","/force" -Wait -NoNewWindow | Out-Null
    } catch { }
}

function Apply-FromRegisteredApp {
    param(
        [string]$Title,
        [string]$Regex,
        [string]$XmlName
    )

    Ensure-AdminOrDie

    $hit = Find-CapabilitiesPathByRegisteredAppNameRegex -NameRegex $Regex
    if (-not $hit) { throw "Не найдено: $Title (нет записи в HKLM:\SOFTWARE\RegisteredApplications)." }

    $appName = Get-CapabilitiesAppName -View $hit.View -CapabilitiesPath $hit.CapPath
    $fileAssocs = Read-CapabilitiesAssociations -View $hit.View -CapabilitiesPath $hit.CapPath -Type FileAssociations
    if ($fileAssocs.Count -eq 0) { throw "У $Title не найдено Capabilities\FileAssociations." }

    $xml = "C:\ProgramData\DefaultAppAssoc\$XmlName"
    Write-DefaultAssociationsXml -OutPath $xml -Associations $fileAssocs -ApplicationName $appName
    Set-DefaultAssociationsPolicy -XmlPath $xml

    Clear-UserChoice -FileExts $fileAssocs.Keys -UrlProtocols @()
    Try-GpUpdate
    Restart-Explorer

    Write-Host "Готово: $Title" -ForegroundColor Green
    Write-Host "Ассоциаций записано: $($fileAssocs.Count)" -ForegroundColor Green
    Write-Host "XML: $xml" -ForegroundColor DarkGray
}

function Apply-7Zip {
    Apply-FromRegisteredApp -Title "7-Zip" -Regex '(?i)7-zip|7zip' -XmlName "defaults-7zip.xml"
}

function Apply-Adobe {
    Apply-FromRegisteredApp -Title "Adobe Reader/Acrobat" -Regex '(?i)acrobat|adobe.*reader|reader.*dc|adobe.*acrobat' -XmlName "defaults-adobe.xml"
}

function Apply-Yandex {
    Ensure-AdminOrDie

    $hit = Find-YandexBrowserCapabilities
    if (-not $hit) { throw "Не найден Yandex Browser в HKLM:\SOFTWARE\Clients\StartMenuInternet." }

    $appName = Get-CapabilitiesAppName -View $hit.View -CapabilitiesPath $hit.CapPath

    $fileAssocs = Read-CapabilitiesAssociations -View $hit.View -CapabilitiesPath $hit.CapPath -Type FileAssociations
    $urlAssocs  = Read-CapabilitiesAssociations -View $hit.View -CapabilitiesPath $hit.CapPath -Type URLAssociations
    if ($fileAssocs.Count -eq 0 -and $urlAssocs.Count -eq 0) {
        throw "У Yandex Browser не найдено Capabilities\FileAssociations/URLAssociations."
    }

    $merged = @{}
    foreach ($k in $fileAssocs.Keys) { $merged[$k] = $fileAssocs[$k] }
    foreach ($k in $urlAssocs.Keys)  { $merged[$k] = $urlAssocs[$k] }

    $xml = "C:\ProgramData\DefaultAppAssoc\defaults-yandex.xml"
    Write-DefaultAssociationsXml -OutPath $xml -Associations $merged -ApplicationName $appName
    Set-DefaultAssociationsPolicy -XmlPath $xml

    Clear-UserChoice -FileExts $fileAssocs.Keys -UrlProtocols $urlAssocs.Keys
    Try-GpUpdate
    Restart-Explorer

    Write-Host "Готово: Yandex Browser" -ForegroundColor Green
    Write-Host "Ассоциаций записано: $($merged.Count) (файлы: $($fileAssocs.Count), протоколы: $($urlAssocs.Count))" -ForegroundColor Green
    Write-Host "XML: $xml" -ForegroundColor DarkGray
}

function Offer-Logoff {
    Write-Host ""
    Write-Host "ВАЖНО: Windows применяет эти дефолты на ВХОДЕ в систему." -ForegroundColor Yellow
    $ans = Read-Host "Сделать выход из системы сейчас? (y/n)"
    if ($ans -match '^(?i)y$') { shutdown /l }
}

# ---- MAIN ----
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
        "0" { return }
        default { Write-Host "Неверный выбор." -ForegroundColor Red }
    }
}
catch {
    Write-Host "Ошибка: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
