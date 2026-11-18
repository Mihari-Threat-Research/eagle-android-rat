# Eagle Android RAT — RAT Android tras una falsa app de citas con abuso de accesibilidad

**Publicado:** 2026-11-17 · **Reporte completo:** [Buscabas el amor en Asia e hiciste "match" con un Malware](https://mihari-intelligence.blogspot.com/2026/11/buscabas-amor-asia-match-malware-cuatro-apk-dos-nucleos-dex.html) · **TLP:CLEAR**

## Resumen

Cuatro APK de Android con hashes distintos (`游戏.apk`, `cupid.apk`, `ROOH-TV.apk` y `123.apk`) comparten el identificador `com.smart.zero.app`, el mismo certificado autofirmado (`CN=TeeEd Local`) y solo dos núcleos de código Dalvik. Detrás de fachadas de juego, televisión y citas, la más llamativa una copia de la portada del sitio legítimo IndonesianCupid, funciona un troyano de acceso remoto que abusa del servicio de accesibilidad. Captura el PIN de bloqueo con falsos diálogos de huella y rostro, registra lo que escribe la víctima, lee SMS y códigos 2FA, vigila notificaciones de banca y criptomonedas (Binance, Coinbase, PayPal, Cash App) y superpone páginas de phishing sobre apps bancarias.

La persistencia combina la omisión del icono en el lanzador, un receptor de arranque con prioridad 999, un widget invisible que se reactiva cada 30 minutos, privilegios de administrador del dispositivo y una falsa pantalla de "actualización del sistema" mientras el operador toma el control. El código crítico está protegido con NMMP (1.128 métodos nativos) y una biblioteca Go empaquetada.

El panel de control asociado, **雄鹰安卓远程管理 ("Eagle Android Remote Management", Eagle 2.0)**, incluye un generador de plantillas de phishing con IA y un constructor de APK. Sus 193 plantillas apuntan a bancos y billeteras de México, Argentina y Ghana.

## Muestra

| Campo | Juego (`游戏.apk`) | `cupid.apk` | `ROOH-TV.apk` | `123.apk` |
|---|---|---|---|---|
| SHA-256 | `f68e48ff…3706598f` | `e48b1117…574b8806` | `5e7488c4…04b45b92` | `0dfb2c60…1347760b` |
| Núcleo DEX | A (con `z/Fix49`) | B | B | B |
| C2 (`serverUrl`) | `rat.668866.net` | `yk.mormonfind.com` | `yk.mormonfind.com` | `yk.mormonfind.com` |
| Icono en el lanzador | Sí | No | No | No |
| Compilación (ZIP) | 2026-11-09 | 2026-10-27 | 2026-10-28 | 2026-10-28 |

Hashes completos (SHA-256, SHA-1 y MD5) en [`iocs/hashes.txt`](iocs/hashes.txt).

| Campo | Valor |
|---|---|
| Paquete | `com.smart.zero.app` (versionCode 90913) |
| Certificado | `CN=TeeEd Local, OU=Build, O=Local, L=SZ, ST=GD, C=CN` · creado 2026-09-22 · SHA-256 `36fe21c231e424ebd2ee54ff079104d93f6068d7836592c8e0577400c49be293` |
| Lenguajes | Kotlin/Java (APK, protegido con NMMP) · Go (`libdxs.so`, `libmedia_codec.so`) |
| Familia | Ecosistema Black Hawk / Eagle Android (ver Atribución) |

## Hallazgos clave

- **Dos núcleos DEX, cuatro envoltorios.** `cupid.apk`, `ROOH-TV.apk` y `123.apk` comparten byte a byte `classes.dex` y `classes2.dex`. Juego añade la clase `z/Fix49`, que intercepta 95 órdenes y guarda las inyecciones en `injection_configs.json` (etiqueta `FIX49INJ`).
- **Falso gemelo.** `123.apk` coincide con `cupid.apk` en 910 de sus 915 entradas, pero su `server_config.json` es idéntico al de `ROOH-TV.apk`.
- **Robo del PIN** mediante `CredentialPromptActivity` y diálogos biométricos que fallan a propósito. El catálogo de órdenes incluye además `DISABLE_BIOMETRIC`, `UNLOCK_DEVICE` y la grabación y reproducción de gestos.
- **ADB inalámbrico** desde `libdxs.so` (Go) con las plantillas `adb pair localhost:%s`, `adb connect 127.0.0.1:%s` y `pm grant %s %s`.
- **Diccionario multilingüe** (`locateValues.json`, 38 idiomas, 13 fabricantes) para reconocer los diálogos de accesibilidad, Play Protect y desinstalación.
- **Bloque de IA inactivo** en la configuración (`aiProvider: deepseek`, `aiModel: deepseek-v4-flash`, clave vacía). Ningún código accesible lo lee. La IA del kit opera en el panel, no en el dispositivo.
- **Sin minería** en el código analizable estáticamente, con la reserva de `libmedia_codec.so`, que sigue sin desempaquetar.

## Contenido del repositorio

| Fichero | Contenido | Validación |
|---|---|---|
| [`iocs/`](iocs) | Hashes de APK, DEX, ELF y recursos, certificado, dominios C2, cadenas y rutas. Incluye `iocs.csv`, listas por tipo (`hashes.txt`, `network.txt`, `host.txt`) y bundle STIX 2.1 | STIX validado |
| [`attack.csv`](attack.csv) | ATT&CK Mobile con evidencia por técnica | IDs y tácticas contrastados con ATT&CK Mobile vigente |
| [`yara/eagle_android.yar`](yara/eagle_android.yar) | 9 reglas para APK/ZIP, `classes.dex`, `libdxs.so` y `server_config.json` | Compilan. Probadas contra las cuatro muestras: cada regla coincide solo con su superficie y su variante |
| [`sigma/`](sigma) | DNS y proxy hacia los dos servidores C2 | Logsources estándar (`dns`, `proxy`) |
| [`suricata/eagle_android.rules`](suricata/eagle_android.rules) | DNS, TLS SNI y HTTP Host de los C2 (SID 1000201-1000206) | Validación en CI |

YARA no descomprime el APK, así que sobre el archivo completo solo responden las dos reglas de contenedor. Las reglas de DEX, ELF y configuración se aplican sobre los ficheros extraídos (`unzip -p muestra.apk classes.dex > classes.dex`, y lo mismo con `lib/arm64-v8a/libdxs.so` y `assets/server_config.json`).

### Cambios respecto a las reglas del blog

- **YARA:** se añadió `MIHARI_HawkQuad_Builder_Config_Template`, que reconoce la plantilla de `server_config.json` del constructor sin depender del dominio C2, la sal ni el operador. Sirve para detectar compilaciones nuevas con servidores aún desconocidos. Las ocho reglas publicadas se mantienen sin cambios.
- **Sigma y Suricata:** nuevas en el repositorio, sobre los dos dominios C2.
- **ATT&CK:** se añadieron T1437.001 (C2 por HTTPS) y T1414 (lectura del portapapeles), que no figuraban en la tabla del blog.
- **IOCs excluidos a propósito:**
  - **`indonesiancupid.com` y `fizzio.tv`** son sitios legítimos usados como cobertura (`webUrl`). No son infraestructura maliciosa y no deben bloquearse.
  - **`dace666.xyz`**, la cobertura de Juego, figura solo en `iocs.csv` con confianza baja y fuera de `network.txt`.
  - **`libspake2.so`, `libnmmp.so` y `libnmmvm.so`** son componentes de terceros que pueden aparecer en aplicaciones legítimas. Figuran en `iocs.csv` con confianza baja, solo para correlación, y fuera de `hashes.txt`. `libconscrypt_jni.so` y `libdatastore_shared_counter.so` no se incluyen.

## Atribución

Sin atribución a un actor concreto. El panel se identifica como 雄鹰安卓远程管理 / Eagle 2.0 y está en chino simplificado, lo que indica el idioma del kit y no el origen del operador. La base analizada coincide con el ecosistema documentado por STAR Labs y Gikaku como Black Hawk / Eagle Android Remote. Las plantillas de México, Argentina y Ghana y la conversión de divisas MXN/USD del panel son indicios de *targeting*, no de atribución.

## Referencias

- STAR Labs — [Two Hawks in a Pod: one Android RAT behind a flock of fake Japanese brands](https://starlabs.sg/blog/2026/10-two-hawks-in-a-pod-one-android-rat-behind-a-flock-of-fake-japanese-brands/)
- Gikaku — [Inside a Japanese e-Tax Android Dropper](https://gikaku.net/2026/10/11/e-tax/)
- MITRE — [ATT&CK Mobile](https://attack.mitre.org/matrices/mobile/)

## Licencia

Reglas, IOCs y documentación bajo [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Ver [LICENSE](LICENSE).

---

**Mihari Threat Research** · [Blog](https://mihari-intelligence.blogspot.com/) · [mihari-intelligence.com](https://mihari-intelligence.com) · TLP:CLEAR
Este repositorio no contiene muestras de malware, solo hashes.
