# Diagnóstico de seguridad para Android (Poco X7 / HyperOS) vía ADB.
# SOLO LECTURA: no instala, borra ni cambia nada en el teléfono.
# No lee mensajes, fotos, contactos ni contraseñas: solo configuración y lista de apps.
#
# Uso (Windows): doble clic en ejecutar_windows.bat
#   o bien:      powershell -ExecutionPolicy Bypass -File diagnostico.ps1
# Requisitos: adb (Android platform-tools) y Depuración USB activada y autorizada.

$ErrorActionPreference = 'Continue'
$adb = if ($env:ADB) { $env:ADB } elseif (Test-Path "$PSScriptRoot\adb.exe") { "$PSScriptRoot\adb.exe" } else { 'adb' }
$out = Join-Path (Get-Location) ("reporte_seguridad_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

# Permisos que suelen pedir el malware bancario y el spyware
$perms = 'SMS|CALL_LOG|CONTACTS|RECORD_AUDIO|CAMERA|LOCATION|READ_PHONE|CALL_PHONE|PROCESS_OUTGOING|ACCOUNTS|BODY_SENSORS|READ_MEDIA|READ_EXTERNAL|MANAGE_EXTERNAL|QUERY_ALL_PACKAGES|REQUEST_INSTALL|SYSTEM_ALERT|PACKAGE_USAGE'

if (-not (Get-Command $adb -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: no se encontró 'adb'. Instala Android platform-tools o copia este script dentro de la carpeta platform-tools." -ForegroundColor Red
    exit 1
}
$state = ((& $adb get-state 2>$null) -join '').Trim()
if ($state -ne 'device') {
    Write-Host "ERROR: no hay un teléfono conectado y autorizado." -ForegroundColor Red
    Write-Host "  - Conecta el cable USB y acepta el aviso 'Permitir depuración USB' en el teléfono."
    Write-Host "  - Si hay varios dispositivos, desconecta los demás."
    exit 1
}

$lines = New-Object System.Collections.Generic.List[string]
function Sh([string]$cmd) { & $adb shell $cmd 2>&1 | ForEach-Object { "$_".TrimEnd("`r") } }
function Sec([string]$t)  { $lines.Add(''); $lines.Add("===== $t =====") }
function Put($x)          { foreach ($l in @($x)) { if ($null -ne $l) { $lines.Add([string]$l) } } }
function Kv([string]$label, [string]$cmd) { $lines.Add(('{0,-34} {1}' -f $label, ((Sh $cmd) -join ' '))) }

Write-Host "Generando reporte, puede tardar 1-3 minutos..."
$lines.Add("REPORTE DE SEGURIDAD ANDROID - " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

Sec "1. DISPOSITIVO"
Kv "Modelo"                    "getprop ro.product.model"
Kv "Fabricante"                "getprop ro.product.manufacturer"
Kv "Android"                   "getprop ro.build.version.release"
Kv "HyperOS / MIUI"            "getprop ro.mi.os.version.incremental; getprop ro.miui.ui.version.name"
Kv "Parche de seguridad"       "getprop ro.build.version.security_patch"
Kv "Build"                     "getprop ro.build.fingerprint"

Sec "2. INTEGRIDAD DEL SISTEMA"
Kv "Verified boot (green=OK)"  "getprop ro.boot.verifiedbootstate"
Kv "Bootloader bloqueado (1)"  "getprop ro.boot.flash.locked"
Kv "Estado vbmeta"             "getprop ro.boot.vbmeta.device_state"
Kv "Build tags (release-keys)" "getprop ro.build.tags"
Kv "ro.debuggable (0=OK)"      "getprop ro.debuggable"
Kv "Binario su (root)"         "which su 2>/dev/null || echo 'no encontrado'"

Sec "3. AJUSTES DE SEGURIDAD"
Kv "Verificar apps (Play Protect)"  "settings get global package_verifier_enable"
Kv "Verificar instalaciones ADB"    "settings get global verifier_verify_adb_installs"
Kv "Orígenes desconocidos (legacy)" "settings get secure install_non_market_apps"
Kv "Opciones de desarrollador"      "settings get global development_settings_enabled"
Kv "Bloqueo de pantalla seguro"     "dumpsys trust 2>/dev/null | grep -m1 -i 'secure' || echo 'n/d'"

Sec "4. RED (proxy, DNS privado, VPN)"
Kv "Proxy HTTP global"         "settings get global http_proxy"
Kv "Proxy host global"         "settings get global global_http_proxy_host"
Kv "DNS privado (modo)"        "settings get global private_dns_mode"
Kv "DNS privado (servidor)"    "settings get global private_dns_specifier"
Kv "VPN siempre activa"        "settings get secure always_on_vpn_app"
Put "-- Redes VPN activas:"
Put (Sh "dumpsys connectivity | grep -i 'VPN' | head -15")

Sec "5. ACCESIBILIDAD, NOTIFICACIONES Y TECLADOS"
Kv "Accesibilidad activa"       "settings get secure accessibility_enabled"
Kv "Servicios de accesibilidad" "settings get secure enabled_accessibility_services"
Kv "Lectores de notificaciones" "settings get secure enabled_notification_listeners"
Kv "Teclado por defecto"        "settings get secure default_input_method"
Kv "Teclados habilitados"       "settings get secure enabled_input_methods"
Kv "App de SMS por defecto"     "settings get secure sms_default_application"

Sec "6. ADMINISTRADORES DEL DISPOSITIVO / PERFILES"
Put (Sh "dumpsys device_policy | grep -iE 'ComponentInfo|owner' | head -40")

Sec "7. PERMISOS ESPECIALES CONCEDIDOS (appops)"
foreach ($op in 'SYSTEM_ALERT_WINDOW','REQUEST_INSTALL_PACKAGES','GET_USAGE_STATS','MANAGE_EXTERNAL_STORAGE','PROJECT_MEDIA','WRITE_SETTINGS') {
    Put "-- ${op}:"
    Put (Sh "cmd appops query-op $op allow")
}

Sec "8. APPS EXENTAS DE OPTIMIZACIÓN DE BATERÍA"
Put (Sh "dumpsys deviceidle whitelist")

Sec "9. APPS INSTALADAS POR EL USUARIO (con instalador)"
Put "(installer=com.android.vending es Play Store; null, com.android.shell, navegadores o gestores de archivos = instalada a mano)"
Put (Sh "pm list packages -3 -i" | Sort-Object)

Sec "10. APPS DE USUARIO SIN ÍCONO EN EL LANZADOR"
$launch = @(Sh "cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER" |
    ForEach-Object { [regex]::Matches($_, '[A-Za-z0-9_.]+(?=/)') | ForEach-Object { $_.Value } } | Sort-Object -Unique)
$pkgs = @(Sh "pm list packages -3" | Where-Object { $_ -like 'package:*' } |
    ForEach-Object { $_.Substring(8).Trim() } | Sort-Object -Unique)
Put ($pkgs | Where-Object { $launch -notcontains $_ })

Sec "11. DETALLE POR APP (fechas, instalador y permisos sensibles concedidos)"
$i = 0
foreach ($p in $pkgs) {
    $i++
    Write-Host ("  [{0}/{1}] {2}" -f $i, $pkgs.Count, $p)
    Put ''
    Put "## $p"
    Put (Sh "dumpsys package $p | grep -E 'versionName=|firstInstallTime=|lastUpdateTime=|installerPackageName=|installInitiatingPackageName=' | sed 's/^ *//' | sort -u")
    Put (Sh "dumpsys package $p | grep 'granted=true' | grep -E '$perms' | sed -E 's/^ *//; s/:.*//' | sort -u | sed 's/^/  + /'")
}

Put ''
Put "===== FIN DEL REPORTE ====="
$lines | Set-Content -Path $out -Encoding UTF8

Write-Host ""
Write-Host "Listo. Reporte guardado en: $out" -ForegroundColor Green
Write-Host "Pégalo o adjúntalo en el chat con Claude para analizarlo."
