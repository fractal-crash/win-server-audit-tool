# Invoke-WindowsServerSecurityAudit

Herramienta ligera y de solo lectura (**read-only**) desarrollada en PowerShell para auditar la configuración de seguridad, exposición y cumplimiento de líneas base (*hardening*) en entornos **Windows Server** (2016, 2019, 2022 y 2025).

El script inspecciona parámetros críticos del sistema operativo, servicios de red, identidades locales, controles de credenciales y criptografía sin realizar modificaciones en la configuración, instalaciones de software ni reinicios de servicios. Al concluir, compila un dashboard interactivo autónomo en HTML junto con evidencias exportadas en archivos CSV.

---

## Características principales

* **100% de solo lectura (*Safe Execution*):** No altera registros, políticas, servicios ni configuraciones de red.
* **Sin dependencias externas:** Diseñado para ejecutarse nativamente en Windows PowerShell 5.1 con cmdlets estándar y WMI/CIM.
* **Entregables ejecutivos y técnicos:**
  * **Dashboard HTML (`Resumen.html`):** Interfaz moderna y responsive con cálculo automático de nivel de riesgo (Bajo, Medio, Alto, Crítico), filtros dinámicos por severidad y tablas expandibles con los datos crudos de cada hallazgo.
  * **Exportación estructurada (`.csv`):** Genera `Hallazgos.csv` para integración directa con herramientas SIEM/GRC y archivos `Evidencia-*.csv` por cada categoría auditada.
  * **Diagnóstico de ejecución (`Diagnostico.txt`):** Registro de validación y control de integridad de la auditoría.

---

## Controles y comprobaciones cubiertas

| Categoría | Identificador | Comprobación y Riesgo Evaluado |
| :--- | :--- | :--- |
| **Plataforma** | `PRIV-001`, `OS-001` | Contexto de privilegios administrativos y ciclo de vida/fin de soporte de Windows Server. |
| **Parcheo** | `PATCH-001` - `003` | Antigüedad del último Cumulative Update instalado y escaneo de actualizaciones de seguridad pendientes vía Windows Update Agent. |
| **Perímetro Local** | `FW-*` | Estado de perfiles de Windows Defender Firewall y política predeterminada de tráfico entrante (*DefaultInboundAction*). |
| **Superficie de Red** | `NET-*` | Puertos TCP en escucha y procesos asociados (inspección de FTP, Telnet, TFTP, POP3, IMAP, SMB 445, RDP 3389, WinRM 5985). |
| **Protocolo SMB** | `SMB-001`, `002` | Detección de protocolo obsoleto SMBv1 y validación de firma digital obligatoria (*SMB Signing*). |
| **Acceso Remoto** | `RDP-001`, `002` | Exposición del servicio RDP y cumplimiento de Network Level Authentication (NLA). |
| **Protección Endpoint**| `AV-001` - `003` | Estado operativo de Microsoft Defender Antivirus / Real-Time Protection y vigencia de firmas de inteligencia. |
| **Credenciales y LSA** | `UAC-001`, `CRED-*` | Estado de User Account Control (UAC), protección RunAsPPL para LSASS y almacenamiento inseguro en WDigest. |
| **Registro y Forense** | `LOG-001`, `AUD-001` | Habilitación de PowerShell Script Block Logging y extracción de directivas avanzadas con `auditpol`. |
| **Criptografía/TLS** | `TLS-10`, `TLS-11` | Configuración explícita de protocolos heredados TLS 1.0 / 1.1 en SCHANNEL (Client y Server). |
| **Identidad Local** | `IAM-001`, `002` | Cuentas con membresía en el grupo local `Administrators` y verificación de deshabilitación de la cuenta Invitado (`RID 501`). |
| **Servicios del SO** | `SVC-001` | Rutas de servicios locales con espacios sin entrecomillar (*Unquoted Service Paths*) en binarios bajo `LocalSystem`. |
| **Hardware y Datos** | `BOOT-001`, `ENC-001` | Estado de validación de Secure Boot (UEFI) y estado de protección/cifrado de volúmenes con BitLocker. |
| **PKI y Certificados** | `CERT-001`, `002` | Inspección del almacén `Cert:\LocalMachine\My` para alertar certificados expirados o próximos a vencer en 30 días. |

---

## Requisitos de ejecución

* **Sistema Operativo:** Windows Server 2012 R2, 2016, 2019, 2022 o 2025.
* **Entorno:** Windows PowerShell 5.1 (o superior).
* **Permisos:** Se requiere ejecutar la consola de PowerShell con privilegios elevados (**Ejecutar como Administrador**) para consultar componentes como BitLocker, perfiles de Firewall, WDigest, certificados locales y políticas de auditoría.

---

## Uso y ejemplos

Abra una consola de PowerShell con privilegios de Administrador y ejecute:

### 1. Ejecución estándar
Genera una carpeta con fecha y hora en el directorio actual conteniendo el reporte HTML y los archivos CSV:
```powershell
.\Invoke-WindowsServerSecurityAudit.ps1
```

### 2. Especificar directorio de salida
```powershell
.\Invoke-WindowsServerSecurityAudit.ps1 -OutputPath "C:\Auditorias\Reporte-DC01"
```

### 3. Omitir el escaneo de Windows Update
Útil para ejecuciones rápidas en entornos desconectados de Internet o sin conectividad al servidor WSUS local:
```powershell
.\Invoke-WindowsServerSecurityAudit.ps1 -SkipWindowsUpdateScan
```

---

## Estructura de salida generada

Al finalizar la ejecución, el directorio de destino contendrá la siguiente estructura:

```text
Server-Security-Audit-<HOSTNAME>-<TIMESTAMP>/
├── Resumen.html                 # Reporte ejecutivo interactivo
├── Diagnostico.txt              # Registro de tiempos, volumen y estado
├── Hallazgos.csv                # Listado tabular de todos los hallazgos
├── Evidencia-Sistema.csv         # Datos de hardware, BIOS y versión del SO
├── Evidencia-Firewall.csv        # Configuración por perfil de firewall
├── Evidencia-SMB.csv             # Parámetros y firma SMB
├── Evidencia-Microsoft-Defender.csv
└── Evidencia-*.csv              # Evidencias segmentadas por módulo
```

---

## Licencia

Este proyecto se distribuye bajo los términos de la licencia [MIT](LICENSE).
