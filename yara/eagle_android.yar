/*
 Mihari Threat Research | Eagle Android RAT (com.smart.zero.app) | TLP:CLEAR
 Reporte: https://mihari-intelligence.blogspot.com/2026/11/buscabas-amor-asia-match-malware-cuatro-apk-dos-nucleos-dex.html
 Aplicar cada regla sobre su superficie correspondiente:
 APK/ZIP, classes.dex extraido, libdxs.so extraido o server_config.json extraido.
 Las reglas 1-8 son las publicadas en el blog. La regla 9 es nueva en este repositorio.
*/
rule MIHARI_HawkQuad_APK_ZIP_Triage
{
meta:
        description = "Huella de empaquetado ZIP/APK compartida por las cuatro muestras"
        author = "Mihari Intelligence"
        date = "2026-11-10"
        sample_scope = "Archivo APK comprimido"
strings:
$z1 = "assets/server_config.json" ascii
$z2 = "assets/app_config.json" ascii
$z3 = "assets/locateValues.json" ascii
$z4 = "lib/arm64-v8a/libdxs.so" ascii
$z5 = "lib/arm64-v8a/libspake2.so" ascii
$z6 = "lib/arm64-v8a/libnmmvm.so" ascii
condition:
uint16(0) == 0x4B50 and filesize < 70MB and all of ($z*)
}

rule MIHARI_HawkQuad_APK_ScreenCurtain_Files
{
meta:
        description = "Rutas ZIP de cortinas de pantalla, biometria falsa y widget keepalive"
        author = "Mihari Intelligence"
        date = "2026-11-10"
        sample_scope = "Archivo APK comprimido"
strings:
$u1 = "res/layout/overlay_android_update.xml" ascii
$u2 = "res/layout/overlay_black.xml" ascii
$u3 = "res/layout/overlay_fingerprint.xml" ascii
$u4 = "res/layout/overlay_face.xml" ascii
$u5 = "res/xml/keepalive_widget_info.xml" ascii
$u6 = "res/anim/pulse_anim.xml" ascii
$lib = "lib/arm64-v8a/libdxs.so" ascii
condition:
uint16(0) == 0x4B50 and filesize < 70MB and $lib and 5 of ($u*)
}

rule MIHARI_HawkQuad_Core_DEX
{
meta:
        description = "Nucleo DEX compartido: accesibilidad, captura de credenciales, inyeccion y DXS"
        author = "Mihari Intelligence"
        date = "2026-11-10"
        sample_scope = "classes.dex EXTRAIDO"
strings:
$s1 = "Lcom/smart/zero/view/service/PlatformAssistDaemon;" ascii
$s2 = "Lcom/smart/zero/view/features/dxs/DxsSetupFlow;" ascii
$s3 = "Lcom/smart/zero/view/features/credential/CredentialPromptActivity;" ascii
$s4 = "Lcom/smart/zero/view/inject/WebPayloadPage;" ascii
$s5 = "Lcom/smart/zero/view/features/payment/InputExtractEngine;" ascii
condition:
uint32(0) == 0x0A786564 and filesize < 50MB and all of ($s*)
}

rule MIHARI_HawkQuad_Juego_Fix49_DEX
{
meta:
        description = "Variante con despachador z/Fix49 y escritura de injection_configs.json"
        author = "Mihari Intelligence"
        date = "2026-11-10"
        sample_scope = "classes.dex EXTRAIDO (variante Juego)"
strings:
$class = "Lz/Fix49;" ascii
$c1 = "USSD_EXECUTE" ascii
$c2 = "ALIPAY_DETECTION_START" ascii
$c3 = "SET_CALL_FORWARDING" ascii
$c4 = "injection_configs.json" ascii
condition:
uint32(0) == 0x0A786564 and filesize < 50MB and $class and 3 of ($c*)
}

rule MIHARI_HawkQuad_DEX_CommandAndOverlay
{
meta:
        description = "Comandos RAT y referencias de overlays en classes.dex"
        author = "Mihari Intelligence"
        date = "2026-11-10"
        sample_scope = "classes.dex EXTRAIDO"
strings:
$cmd1 = "KEYLOG_START" ascii
$cmd2 = "CMD_SMS_READ" ascii
$ov1 = "overlay_android_update" ascii
$ov2 = "overlay_fingerprint" ascii
$ov3 = "overlay_face" ascii
$dxs = "Lcom/smart/zero/view/features/dxs/DxsSetupFlow;" ascii
condition:
uint32(0) == 0x0A786564 and filesize < 50MB and all of ($cmd*) and 2 of ($ov*) and $dxs
}

rule MIHARI_HawkQuad_LibDXS_ADB_Strings
{
meta:
        description = "Marcas de emparejamiento ADB inalambrico y concesion de permisos en libdxs.so"
        author = "Mihari Intelligence"
        date = "2026-11-10"
        sample_scope = "lib/arm64-v8a/libdxs.so EXTRAIDO"
strings:
$a1 = "adb pair localhost:" ascii
$a2 = "adb connect 127.0.0.1:" ascii
$a3 = "pm grant %s %s" ascii
condition:
uint32(0) == 0x464C457F and filesize < 30MB and all of ($a*)
}

rule MIHARI_HawkQuad_Config_A_JSON
{
meta:
        description = "Configuracion C2 perfil A (Juego): servidor, operador y sal"
        author = "Mihari Intelligence"
        date = "2026-11-10"
        sample_scope = "assets/server_config.json EXTRAIDO"
strings:
$server = "rat.668866.net" ascii
$user = "dace666" ascii
$salt = "4bdbb100f8575d7471e86c6aaa5504bc" ascii
$key = "\"serverUrl\"" ascii
condition:
filesize < 100KB and all of them
}

rule MIHARI_HawkQuad_Config_B_JSON
{
meta:
        description = "Configuracion C2 perfil B (Cupid, ROOH-TV, 123): servidor, operador y sal"
        author = "Mihari Intelligence"
        date = "2026-11-10"
        sample_scope = "assets/server_config.json EXTRAIDO"
strings:
$server = "yk.mormonfind.com" ascii
$user = "ykadmin" ascii
$salt = "fa50709080bc630f92b92dd2e8268fcd" ascii
$key = "\"serverUrl\"" ascii
condition:
filesize < 100KB and all of them
}

rule MIHARI_HawkQuad_Builder_Config_Template
{
meta:
        description = "Plantilla de configuracion del constructor Eagle con independencia del servidor C2"
        author = "Mihari Threat Research"
        date = "2026-11-18"
        sample_scope = "assets/server_config.json EXTRAIDO"
        note = "Nueva en el repositorio. Detecta compilaciones con servidores C2 aun no conocidos"
strings:
$k1 = "\"deviceKeySalt\"" ascii
$k2 = "\"dxsConfig\"" ascii
$k3 = "\"paymentBypassApps\"" ascii
$k4 = "\"enableConfigMask\"" ascii
$k5 = "\"ownerUsername\"" ascii
$k6 = "\"aiProvider\"" ascii
$k7 = "\"enableServiceMode\"" ascii
$url = "\"serverUrl\"" ascii
condition:
filesize < 100KB and $url and 6 of ($k*)
}
