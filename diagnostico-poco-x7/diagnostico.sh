#!/usr/bin/env bash
# Diagnóstico de seguridad para Android (Poco X7 / HyperOS) vía ADB.
# SOLO LECTURA: no instala, borra ni cambia nada en el teléfono.
# No lee mensajes, fotos, contactos ni contraseñas: solo configuración y lista de apps.
#
# Uso (macOS / Linux):   bash diagnostico.sh
# Requisitos: adb (Android platform-tools) y Depuración USB activada y autorizada.

set -u
ADB="${ADB:-adb}"
OUT="reporte_seguridad_$(date +%Y%m%d_%H%M%S).txt"

# Permisos que suelen pedir el malware bancario y el spyware
PERMS='SMS|CALL_LOG|CONTACTS|RECORD_AUDIO|CAMERA|LOCATION|READ_PHONE|CALL_PHONE|PROCESS_OUTGOING|ACCOUNTS|BODY_SENSORS|READ_MEDIA|READ_EXTERNAL|MANAGE_EXTERNAL|QUERY_ALL_PACKAGES|REQUEST_INSTALL|SYSTEM_ALERT|PACKAGE_USAGE'

if ! command -v "$ADB" >/dev/null 2>&1; then
  echo "ERROR: no se encontró 'adb'. Instala Android platform-tools y vuelve a intentar."
  exit 1
fi
if [ "$("$ADB" get-state 2>/dev/null)" != "device" ]; then
  echo "ERROR: no hay un teléfono conectado y autorizado."
  echo "  - Conecta el cable USB y acepta el aviso 'Permitir depuración USB' en el teléfono."
  echo "  - Si hay varios dispositivos, desconecta los demás."
  exit 1
fi

sh_() { "$ADB" shell "$1" 2>&1 | tr -d '\r'; }
sec() { printf '\n===== %s =====\n' "$1"; }
kv()  { printf '%-34s %s\n' "$1" "$(sh_ "$2")"; }

echo "Generando reporte, puede tardar 1-3 minutos..."

{
  echo "REPORTE DE SEGURIDAD ANDROID - $(date '+%Y-%m-%d %H:%M:%S')"

  sec "1. DISPOSITIVO"
  kv "Modelo"                    "getprop ro.product.model"
  kv "Fabricante"                "getprop ro.product.manufacturer"
  kv "Android"                   "getprop ro.build.version.release"
  kv "HyperOS / MIUI"            "getprop ro.mi.os.version.incremental; getprop ro.miui.ui.version.name"
  kv "Parche de seguridad"       "getprop ro.build.version.security_patch"
  kv "Build"                     "getprop ro.build.fingerprint"

  sec "2. INTEGRIDAD DEL SISTEMA"
  kv "Verified boot (green=OK)"  "getprop ro.boot.verifiedbootstate"
  kv "Bootloader bloqueado (1)"  "getprop ro.boot.flash.locked"
  kv "Estado vbmeta"             "getprop ro.boot.vbmeta.device_state"
  kv "Build tags (release-keys)" "getprop ro.build.tags"
  kv "ro.debuggable (0=OK)"      "getprop ro.debuggable"
  kv "Binario su (root)"         "which su 2>/dev/null || echo 'no encontrado'"

  sec "3. AJUSTES DE SEGURIDAD"
  kv "Verificar apps (Play Protect)" "settings get global package_verifier_enable"
  kv "Verificar instalaciones ADB"   "settings get global verifier_verify_adb_installs"
  kv "Orígenes desconocidos (legacy)" "settings get secure install_non_market_apps"
  kv "Opciones de desarrollador"     "settings get global development_settings_enabled"
  kv "Bloqueo de pantalla seguro"    "dumpsys trust 2>/dev/null | grep -m1 -i 'secure' || echo 'n/d'"

  sec "4. RED (proxy, DNS privado, VPN)"
  kv "Proxy HTTP global"         "settings get global http_proxy"
  kv "Proxy host global"         "settings get global global_http_proxy_host"
  kv "DNS privado (modo)"        "settings get global private_dns_mode"
  kv "DNS privado (servidor)"    "settings get global private_dns_specifier"
  kv "VPN siempre activa"        "settings get secure always_on_vpn_app"
  echo "-- Redes VPN activas:"
  sh_ "dumpsys connectivity | grep -i 'VPN' | head -15"

  sec "5. ACCESIBILIDAD, NOTIFICACIONES Y TECLADOS"
  kv "Accesibilidad activa"      "settings get secure accessibility_enabled"
  kv "Servicios de accesibilidad" "settings get secure enabled_accessibility_services"
  kv "Lectores de notificaciones" "settings get secure enabled_notification_listeners"
  kv "Teclado por defecto"       "settings get secure default_input_method"
  kv "Teclados habilitados"      "settings get secure enabled_input_methods"
  kv "App de SMS por defecto"    "settings get secure sms_default_application"

  sec "6. ADMINISTRADORES DEL DISPOSITIVO / PERFILES"
  sh_ "dumpsys device_policy | grep -iE 'ComponentInfo|owner' | head -40"

  sec "7. PERMISOS ESPECIALES CONCEDIDOS (appops)"
  for op in SYSTEM_ALERT_WINDOW REQUEST_INSTALL_PACKAGES GET_USAGE_STATS MANAGE_EXTERNAL_STORAGE PROJECT_MEDIA WRITE_SETTINGS; do
    echo "-- $op:"
    sh_ "cmd appops query-op $op allow"
  done

  sec "8. APPS EXENTAS DE OPTIMIZACIÓN DE BATERÍA"
  sh_ "dumpsys deviceidle whitelist"

  sec "9. APPS INSTALADAS POR EL USUARIO (con instalador)"
  echo "(installer=com.android.vending es Play Store; null, com.android.shell, navegadores o gestores de archivos = instalada a mano)"
  sh_ "pm list packages -3 -i" | sort

  sec "10. APPS DE USUARIO SIN ÍCONO EN EL LANZADOR"
  launchable=$(sh_ "cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER" \
               | grep -oE '[A-Za-z0-9_.]+/' | tr -d '/' | sort -u)
  pkgs=$(sh_ "pm list packages -3" | sed -E 's/^package://' | sort -u)
  comm -23 <(printf '%s\n' "$pkgs") <(printf '%s\n' "$launchable")

  sec "11. DETALLE POR APP (fechas, instalador y permisos sensibles concedidos)"
  total=$(printf '%s\n' "$pkgs" | grep -c .)
  i=0
  for p in $pkgs; do
    i=$((i+1))
    printf '  [%d/%d] %s\n' "$i" "$total" "$p" >&2
    echo
    echo "## $p"
    sh_ "dumpsys package $p | grep -E 'versionName=|firstInstallTime=|lastUpdateTime=|installerPackageName=|installInitiatingPackageName=' | sed 's/^ *//' | sort -u"
    sh_ "dumpsys package $p | grep 'granted=true' | grep -E '$PERMS' | sed -E 's/^ *//; s/:.*//' | sort -u | sed 's/^/  + /'"
  done

  echo
  echo "===== FIN DEL REPORTE ====="
} > "$OUT"

echo
echo "Listo. Reporte guardado en: $(pwd)/$OUT"
echo "Pégalo o adjúntalo en el chat con Claude para analizarlo."
