# Switch-Defaults.ps1
# Переключение дефолтных ассоциаций в Windows 11 через DefaultAppAssociations XML + Policy (HKLM)
# 1) 7-Zip: все расширения из Capabilities\FileAssociations
# 2) Adobe Reader/Acrobat: все расширения из Capabilities\FileAssociations
# 3) Yandex Browser: протоколы (http/https и др.) + web-расширения из Capabilities\URLAssociations и FileAssociations
#
# Требуются права администратора.
# Применение ассоциаций происходит при следующем входе в систему (лучше сделать "выход" и войти снова).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-AdminOrFail {
    if (-not (Test-IsAdmin)) {
        throw "Нужны права администратора. Запусти через CMD-лаунчер (он поднимет UAC) или запусти PowerShell от имени администратора."
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
    }
    finally { $base.Close() }
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
        }
        finally { $key.Close() }
    }
    finally { $base.Close() }
}

function Get-RegValue {
    param([Microsoft.Win32.RegistryHive]$Hive, [Microsoft.Win32.RegistryView]$View, [string]$SubKeyPath, [string]$ValueName)
    $base = Open-BaseKey -Hive $Hive -View $View
    try {
        $key = $base.OpenSubKey($SubKeyPath)
        if (-not $key) { return $null }
        try { return $key.GetValue($ValueName) }
        finally { $key.Close() }
    }
    finally { $base.Close() }
}

function Find-CapabilitiesPathByRegisteredAppNameRegex {
    param([string]$NameRegex)

    $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
    foreach ($view in $views) {
        $regApps = Get-RegValueMap -Hive LocalMachine -View $view -SubKeyPath 'SOFTWARE\RegisteredApplications'
        foreach ($k in $regApps.Keys) {
            if ($k -match $NameRegex) {
                return @{ View = $view; CapPath = $regApps[$k] } # например SOFTWARE\7-Zip\Capabilities
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

    return Get-RegValueMap -Hive LocalMachine -View $View -SubKeyPath $sub
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
    # HKLM\SOFTWARE\Clients\StartMenuInternet\<browser>\Capabilities
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
            }
            finally { $root.Close() }
        }
        finally { $base.Close() }
    }

    return $null
}

function Write-DefaultAssociationsXml {
    param(
        [string]$OutPath,
        [hashtable]$Associations,
        [string]$ApplicationName
    )

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
        if (Test-Path $p) {
            Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($proto in $UrlProtocols | Sort-Object -Unique) {
        $p = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$proto\UserChoice"
        if (Test-Path $p) {
            Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Restart-Explorer {
    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Process explorer.exe | Out-Null
}

function Apply-7Zip {
    Ensure-AdminOrFail

    $hit = Find-CapabilitiesPathByRegisteredAppNameRegex -NameRegex '(?i)7-zip|7zip'
    if (-not $hit) { throw "Не нашёл 7-Zip в HKLM:\SOFTWARE\RegisteredApplications (приложение не установлено или не зарегистрировало Capabilities)." }

    $appName = Get-CapabilitiesAppName -View $hit.View -CapabilitiesPath $hit.CapPath
    $fileAssocs = Read-CapabilitiesAssociations -View $hit.View -CapabilitiesPath $hit.CapPath -Type FileAssociations
    if ($fileAssocs.Count -eq 0) { throw "У 7-Zip не найдено Capabilities\FileAssociations." }

    $xml = "C:\ProgramData\DefaultAppAssoc\defaults-7zip.xml"
    Write-DefaultAssociationsXml -OutPath $xml -Associations $fileAssocs -ApplicationName $appName
    Set-DefaultAssociationsPolicy -XmlPath $xml

    Clear-UserChoice -FileExts $fileAssocs.Keys -UrlProtocols @()
    Restart-Explorer

    Write-Host "7-Zip: записано ассоциаций: $($fileAssocs.Count)" -ForegroundColor Green
    Write-Host "Политика указывает на: $xml" -ForegroundColor Green
}

function Apply-Adobe {
    Ensure-AdminOrFail

    $hit = Find-CapabilitiesPathByRegisteredAppNameRegex -NameRegex '(?i)acrobat|adobe.*reader|reader.*dc|adobe.*acrobat'
    if (-not $hit) { throw "Не нашёл Adobe Reader/Acrobat в HKLM:\SOFTWARE\RegisteredApplications." }

    $appName = Get-CapabilitiesAppName -View $hit.View -CapabilitiesPath $hit.CapPath
    $fileAssocs = Read-CapabilitiesAssociations -View $hit.View -CapabilitiesPath $hit.CapPath -Type FileAssociations
    if ($fileAssocs.Count -eq 0) { throw "У Adobe Reader/Acrobat не найдено Capabilities\FileAssociations." }

    $xml = "C:\ProgramData\DefaultAppAssoc\defaults-adobe.xml"
    Write-DefaultAssociationsXml -OutPath $xml -Associations $fileAssocs -ApplicationName $appName
    Set-DefaultAssociationsPolicy -XmlPath $xml

    Clear-UserChoice -FileExts $fileAssocs.Keys -UrlProtocols @()
    Restart-Explorer

    Write-Host "Adobe: записано ассоциаций: $($fileAssocs.Count)" -ForegroundColor Green
    Write-Host "Политика указывает на: $xml" -ForegroundColor Green
}

function Apply-Yandex {
    Ensure-AdminOrFail

    $hit = Find-YandexBrowserCapabilities
    if (-not $hit) { throw "Не нашёл Yandex Browser в HKLM:\SOFTWARE\Clients\StartMenuInternet (не установлен/не зарегистрирован как браузер)." }

    $appName = Get-CapabilitiesAppName -View $hit.View -CapabilitiesPath $hit.CapPath

    # У браузера это не RegisteredApplications, а Clients\StartMenuInternet\<...>\Capabilities\{FileAssociations,URLAssociations}
    $fileAssocs = Read-CapabilitiesAssociations -View $hit.View -CapabilitiesPath $hit.CapPath -Type FileAssociations
    $urlAssocs  = Read-CapabilitiesAssociations -View $hit.View -CapabilitiesPath $hit.CapPath -Type URLAssociations

    if ($fileAssocs.Count -eq 0 -and $urlAssocs.Count -eq 0) {
        throw "У Yandex Browser не найдено Capabilities\URLAssociations и/или FileAssociations."
    }

    $merged = @{}
    foreach ($k in $fileAssocs.Keys) { $merged[$k] = $fileAssocs[$k] }
    foreach ($k in $urlAssocs.Keys)  { $merged[$k] = $urlAssocs[$k] }

    $xml = "C:\ProgramData\DefaultAppAssoc\defaults-yandex.xml"
    Write-DefaultAssociationsXml -OutPath $xml -Associations $merged -ApplicationName $appName
    Set-DefaultAssociationsPolicy -XmlPath $xml

    Clear-UserChoice -FileExts $fileAssocs.Keys -UrlProtocols $urlAssocs.Keys
    Restart-Explorer

    Write-Host "Yandex: записано ассоциаций: $($merged.Count) (файлы: $($fileAssocs.Count), протоколы: $($urlAssocs.Count))" -ForegroundColor Green
    Write-Host "Политика указывает на: $xml" -ForegroundColor Green
}

function Prompt-Logoff {
    Write-Host ""
    Write-Host "ВАЖНО: новые дефолты применятся при следующем входе в систему." -ForegroundColor Yellow
    $ans = Read-Host "Сделать выход из системы сейчас? (y/n)"
    if ($ans -match '^(?i)y$') { shutdown /l }
}

# ---- MAIN ----
try {
    Write-Host ""
    Write-Host "Что сделать?" -ForegroundColor Cyan
    Write-Host "  1) Ассоциации -> 7-Zip"
    Write-Host "  2) Ассоциации -> Adobe Reader/Acrobat"
    Write-Host "  3) Ассоциации -> Yandex Browser (включая http/https)"
    Write-Host "  0) Выход"
    Write-Host ""

    $choice = Read-Host "Введи 0, 1, 2 или 3"

    switch ($choice) {
        "1" { Apply-7Zip;  Prompt-Logoff }
        "2" { Apply-Adobe; Prompt-Logoff }
        "3" { Apply-Yandex; Prompt-Logoff }
        "0" { return }
        default { Write-Host "Неверный выбор." -ForegroundColor Red }
    }
}
catch {
    Write-Host "Ошибка: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.Exception.ToString() -ForegroundColor DarkGray
    exit 1
}
