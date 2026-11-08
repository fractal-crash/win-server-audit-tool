# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/)
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-07

### Añadido
- Versión inicial del script de auditoría de seguridad para Windows Server (`Invoke-WindowsServerSecurityAudit.ps1`).
- Módulo de recolección de metadatos de hardware, BIOS y versión de sistema operativo.
- Auditoría de parches instalados y escaneo opcional de pendientes vía Windows Update Agent (`-SkipWindowsUpdateScan`).
- Validación de configuración de Windows Defender Firewall (perfiles Domain, Private, Public).
- Detección de puertos TCP en estado de escucha vinculados a procesos propietarios.
- Verificación de obsolescencia de SMBv1 y requerimiento de firmas SMB (*SMB Signing*).
- Análisis de configuración y autenticación a nivel de red (NLA) para Remote Desktop (RDP).
- Inspección de estado de Microsoft Defender (Antivirus, tiempo real, vigencia de firmas).
- Comprobación de controles de aislamiento de credenciales (UAC, LSA Protection `RunAsPPL`, WDigest).
- Detección de configuración de auditoría avanzada (`auditpol`) y registro de scripts de PowerShell (*Script Block Logging*).
- Detección de protocolos débiles TLS 1.0 y 1.1 en el proveedor SCHANNEL.
- Revisión de miembros del grupo local `Administrators` y validación de la cuenta de Invitado.
- Inspección de rutas de servicio con espacios sin comillas (*Unquoted Service Paths*) en servicios `LocalSystem`.
- Verificación del estado de Secure Boot (UEFI) y cifrado de volumen BitLocker.
- Verificación de certificados SSL/TLS expirados o próximos a expirar en `LocalMachine\My`.
- Exportación automatizada a formatos `Resumen.html` interactivo y matrices tabulares `.csv`.
- Manejo robusto de errores mediante bloques `Invoke-SafeCheck` y generación de bitácora `Diagnostico.txt`.
