#requires -Version 5.1
<#
.SYNOPSIS
  Auditoria de seguridad de solo lectura para Windows Server.
.DESCRIPTION
  Recolecta configuracion local, conserva los objetos PowerShell originales y genera
  un reporte HTML ejecutivo con tablas construidas desde PSObject.Properties.
  No modifica configuraciones, no instala software y no corrige hallazgos.
.EXAMPLE
  .\Invoke-WindowsServerSecurityAudit.ps1
  .\Invoke-WindowsServerSecurityAudit.ps1 -OutputPath C:\AuditoriaServidor
  .\Invoke-WindowsServerSecurityAudit.ps1 -SkipWindowsUpdateScan
.NOTES
  Ejecutar en Windows PowerShell 5.1 como administrador para obtener cobertura completa.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) ("Server-Security-Audit-{0}-{1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$SkipWindowsUpdateScan
)

$ErrorActionPreference = 'Continue'
$script:OriginalErrorActionPreference = $ErrorActionPreference
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Sections = New-Object System.Collections.Generic.List[object]
$script:Errors = New-Object System.Collections.Generic.List[object]
$script:StartTime = Get-Date

function ConvertTo-HtmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Add-AuditError {
    param([string]$Check,[string]$Message)
    [void]$script:Errors.Add([pscustomobject]@{Comprobacion=$Check;Mensaje=$Message})
}

function Invoke-SafeCheck {
    param([string]$Name,[scriptblock]$ScriptBlock)
    try { & $ScriptBlock }
    catch {
        Add-AuditError $Name $_.Exception.Message
        $null
    }
}

function Add-ReportSection {
    param(
        [string]$Name,
        [string]$Description,
        [AllowNull()][object]$Data
    )
    $items = @($Data | Where-Object { $null -ne $_ })
    [void]$script:Sections.Add([pscustomobject]@{
        Nombre=$Name
        Descripcion=$Description
        Datos=$items
        Cantidad=$items.Count
    })
}

function Add-Finding {
    param(
        [string]$Id,
        [ValidateSet('Critica','Alta','Media','Baja','Informativa')][string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Evidence,
        [string]$Risk,
        [string]$Recommendation,
        [string]$Reference,
        [AllowNull()][object]$Data
    )
    $items = @($Data | Where-Object { $null -ne $_ })
    [void]$script:Findings.Add([pscustomobject]@{
        Id=$Id; Severidad=$Severity; Categoria=$Category; Hallazgo=$Title
        Evidencia=$Evidence; Riesgo=$Risk; Recomendacion=$Recommendation
        Referencia=$Reference; Datos=$items; Cantidad=$items.Count
    })
}

function Get-RegValue {
    param([string]$Path,[string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

function Test-IsAdministrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Convert-ValueForHtml {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return (ConvertTo-HtmlText ($Value.ToString('yyyy-MM-dd HH:mm:ss'))) }
    if ($Value -is [bool]) { if ($Value) { return 'Si' } else { return 'No' } }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return ConvertTo-HtmlText (@($Value) -join '; ')
    }
    ConvertTo-HtmlText $Value
}

function Convert-ObjectsToHtmlTable {
    param(
        [AllowNull()][object]$Data,
        [int]$MaxRows=1000
    )
    $items=@($Data | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) { return '<p class="empty">Sin datos devueltos por esta comprobacion.</p>' }

    if ($items[0] -is [string] -or $items[0].GetType().IsPrimitive) {
        $items=@($items | ForEach-Object { [pscustomobject]@{Valor=$_} })
    }

    $columns=New-Object System.Collections.Generic.List[string]
    foreach($item in ($items | Select-Object -First 25)) {
        foreach($prop in $item.PSObject.Properties) {
            if($prop.MemberType -in 'NoteProperty','Property','AliasProperty' -and -not $columns.Contains($prop.Name)) {
                [void]$columns.Add($prop.Name)
            }
        }
    }
    if($columns.Count -eq 0) { return '<p class="empty">Los objetos no exponen propiedades presentables.</p>' }

    $sb=New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-scroll"><table class="data"><thead><tr>')
    foreach($c in $columns){[void]$sb.Append('<th>'+ (ConvertTo-HtmlText $c) +'</th>')}
    [void]$sb.Append('</tr></thead><tbody>')
    foreach($row in ($items | Select-Object -First $MaxRows)) {
        [void]$sb.Append('<tr>')
        foreach($c in $columns) {
            $value=$null
            $property=$row.PSObject.Properties[$c]
            if($null -ne $property){$value=$property.Value}
            [void]$sb.Append('<td>'+ (Convert-ValueForHtml $value) +'</td>')
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if($items.Count -gt $MaxRows){[void]$sb.Append("<p class='note'>Se muestran $MaxRows de $($items.Count) registros.</p>")}
    $sb.ToString()
}

# -----------------------------------------------------------------------------
# Recoleccion
# -----------------------------------------------------------------------------
$admin=Test-IsAdministrator
$os=Invoke-SafeCheck 'Sistema operativo' { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
$cs=Invoke-SafeCheck 'Sistema de computo' { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
$bios=Invoke-SafeCheck 'BIOS' { Get-CimInstance Win32_BIOS -ErrorAction Stop }

$systemInfo=[pscustomobject]@{
    Equipo=$env:COMPUTERNAME
    SistemaOperativo=$os.Caption
    Version=$os.Version
    Build=$os.BuildNumber
    Arquitectura=$os.OSArchitecture
    Dominio=$cs.Domain
    Fabricante=$cs.Manufacturer
    Modelo=$cs.Model
    MemoriaGB=if($cs.TotalPhysicalMemory){[math]::Round($cs.TotalPhysicalMemory/1GB,2)}else{$null}
    UltimoArranque=$os.LastBootUpTime
    BIOS=$bios.SMBIOSBIOSVersion
    EjecutadoComoAdministrador=$admin
}
Add-ReportSection 'Sistema' 'Identidad, plataforma y contexto de ejecucion.' $systemInfo
if(-not $admin){Add-Finding 'PRIV-001' 'Media' 'Ejecucion' 'Auditoria ejecutada sin privilegios administrativos' 'Algunas consultas pueden devolver datos incompletos.' 'Puede producir falsos negativos.' 'Ejecutar nuevamente como administrador.' 'Windows security auditing' $systemInfo}
if($os.Caption -match '2008|2012'){Add-Finding 'OS-001' 'Critica' 'Sistema operativo' 'Version de Windows Server antigua o fuera de soporte general' $os.Caption 'Puede no recibir correcciones sin ESU.' 'Migrar a Windows Server 2022/2025 o confirmar cobertura ESU.' 'Microsoft Product Lifecycle' $systemInfo}

$hotfixes=@(Invoke-SafeCheck 'Hotfixes' { Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledBy,InstalledOn })
Add-ReportSection 'Actualizaciones instaladas' 'Hotfixes reportados por Get-HotFix.' $hotfixes
$latest=$hotfixes | Where-Object InstalledOn | Select-Object -First 1
if(-not $latest){Add-Finding 'PATCH-001' 'Alta' 'Parches' 'No se pudo determinar la ultima actualizacion instalada' 'Get-HotFix no devolvio una fecha util.' 'No se confirma el nivel de parcheo.' 'Validar en WSUS, Azure Update Manager o la plataforma corporativa.' 'MSRC Security Update Guide' $hotfixes}
elseif(((Get-Date)-$latest.InstalledOn).TotalDays -gt 45){Add-Finding 'PATCH-002' 'Alta' 'Parches' 'No hay evidencia de parches recientes' ("Ultimo hotfix: {0}; instalado: {1}" -f $latest.HotFixID,$latest.InstalledOn) 'Aumenta la exposicion a vulnerabilidades conocidas.' 'Probar y desplegar actualizaciones acumulativas aplicables.' 'MSRC Security Update Guide' $latest}

$pending=@()
if(-not $SkipWindowsUpdateScan){
    $pending=@(Invoke-SafeCheck 'Windows Update pendientes' {
        $session=New-Object -ComObject Microsoft.Update.Session
        $result=$session.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')
        @($result.Updates | ForEach-Object {[pscustomobject]@{Titulo=$_.Title;SeveridadMSRC=$_.MsrcSeverity;KB=($_.KBArticleIDs -join ',');RequiereReinicio=$_.RebootRequired}})
    })
    Add-ReportSection 'Actualizaciones pendientes' 'Resultados de Windows Update Agent en modo Search.' $pending
    $security=@($pending | Where-Object {$_.Titulo -match 'Security|Seguridad|Critical|Critica|Cumulative|Acumulativa' -or $_.SeveridadMSRC})
    if($security.Count -gt 0){Add-Finding 'PATCH-003' 'Alta' 'Parches' 'Actualizaciones de seguridad pendientes' ("Detectadas: {0}" -f $security.Count) 'Puede haber CVE corregidas aun no instaladas.' 'Correlacionar KB con MSRC/CISA KEV, probar y desplegar.' 'Windows Update Agent / MSRC' $security}
}else{Add-ReportSection 'Actualizaciones pendientes' 'Comprobacion omitida por parametro.' ([pscustomobject]@{Estado='Omitida';Parametro='SkipWindowsUpdateScan'})}

$firewall=@(Invoke-SafeCheck 'Firewall' { Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,NotifyOnListen })
Add-ReportSection 'Firewall' 'Perfiles de Windows Defender Firewall.' $firewall
foreach($p in $firewall){
    if(-not $p.Enabled){Add-Finding ("FW-{0}" -f $p.Name) 'Alta' 'Firewall' ("Firewall deshabilitado: {0}" -f $p.Name) 'Enabled=False' 'Incrementa la superficie de ataque.' 'Habilitar mediante GPO despues de validar reglas.' 'Microsoft Security Baseline' $p}
    if($p.DefaultInboundAction -eq 'Allow'){Add-Finding ("FW-IN-{0}" -f $p.Name) 'Alta' 'Firewall' ("Entrada permitida por defecto: {0}" -f $p.Name) 'DefaultInboundAction=Allow' 'Servicios no previstos pueden quedar accesibles.' 'Aplicar bloqueo predeterminado y excepciones explicitas.' 'Microsoft Security Baseline' $p}
}

$listeners=@(Invoke-SafeCheck 'Puertos TCP' { Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {$proc=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;[pscustomobject]@{DireccionLocal=$_.LocalAddress;PuertoLocal=$_.LocalPort;PID=$_.OwningProcess;Proceso=$proc.ProcessName}} | Sort-Object PuertoLocal,Proceso -Unique })
Add-ReportSection 'Puertos TCP en escucha' 'Puertos locales y procesos propietarios.' $listeners
foreach($port in 21,23,69,110,143,445,3389,5985){$hit=@($listeners | Where-Object PuertoLocal -eq $port);if($hit.Count -gt 0){$sev=if($port -in 21,23,69){'Alta'}else{'Media'};Add-Finding ("NET-{0}" -f $port) $sev 'Red' ("Puerto sensible en escucha: {0}" -f $port) ("Instancias: {0}" -f $hit.Count) 'Puede facilitar administracion remota, protocolos heredados o movimiento lateral.' 'Confirmar necesidad, limitar origen mediante firewall y usar cifrado.' 'Microsoft Security Baseline / CIS' $hit}}

$smb1=Invoke-SafeCheck 'SMB1' { (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State }
$smb=Invoke-SafeCheck 'SMB Server' { Get-SmbServerConfiguration -ErrorAction Stop }
$smbData=[pscustomobject]@{SMB1=$smb1;EnableSMB1Protocol=$smb.EnableSMB1Protocol;EnableSMB2Protocol=$smb.EnableSMB2Protocol;RequireSecuritySignature=$smb.RequireSecuritySignature;EnableSecuritySignature=$smb.EnableSecuritySignature;EncryptData=$smb.EncryptData;RejectUnencryptedAccess=$smb.RejectUnencryptedAccess}
Add-ReportSection 'SMB' 'Configuracion del servidor SMB.' $smbData
if($smb1 -eq 'Enabled' -or $smb.EnableSMB1Protocol){Add-Finding 'SMB-001' 'Critica' 'SMB' 'SMBv1 habilitado' 'SMB1 activo.' 'Protocolo obsoleto asociado con ransomware y movimiento lateral.' 'Identificar dependencias y deshabilitar SMBv1.' 'Microsoft Security Baseline' $smbData}
if($smb -and -not $smb.RequireSecuritySignature){Add-Finding 'SMB-002' 'Alta' 'SMB' 'Firma SMB no requerida' 'RequireSecuritySignature=False' 'Facilita ataques de retransmision.' 'Exigir firma SMB mediante GPO tras probar compatibilidad.' 'Microsoft Security Baseline' $smbData}

$rdpDeny=Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$nla=Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
$rdpPort=Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
$rdpData=[pscustomobject]@{RDPHabilitado=($rdpDeny -eq 0);NLA=($nla -eq 1);Puerto=$rdpPort;fDenyTSConnections=$rdpDeny;UserAuthentication=$nla}
Add-ReportSection 'RDP' 'Estado de Escritorio remoto y Network Level Authentication.' $rdpData
if($rdpDeny -eq 0 -and $nla -ne 1){Add-Finding 'RDP-001' 'Alta' 'Acceso remoto' 'RDP habilitado sin NLA confirmado' "fDenyTSConnections=$rdpDeny; UserAuthentication=$nla" 'Aumenta la exposicion previa a autenticacion.' 'Exigir NLA, MFA con RD Gateway/Entra y limitar origen.' 'Microsoft RDP security guidance' $rdpData}
elseif($rdpDeny -eq 0){Add-Finding 'RDP-002' 'Media' 'Acceso remoto' 'RDP habilitado' 'NLA detectado.' 'RDP sigue siendo objetivo frecuente si tiene alcance amplio.' 'Limitar a red de administracion o RD Gateway y aplicar MFA.' 'Microsoft RDP security guidance' $rdpData}

$defender=Invoke-SafeCheck 'Microsoft Defender' { Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,NISEnabled,AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge,IsTamperProtected }
Add-ReportSection 'Microsoft Defender' 'Estado del antivirus y protecciones en tiempo real.' $defender
if($defender){
    if(-not $defender.AntivirusEnabled -or -not $defender.RealTimeProtectionEnabled){Add-Finding 'AV-001' 'Critica' 'Antimalware' 'Proteccion antivirus o en tiempo real deshabilitada' ("Antivirus={0}; TiempoReal={1}" -f $defender.AntivirusEnabled,$defender.RealTimeProtectionEnabled) 'Reduce la prevencion y deteccion de malware.' 'Confirmar otro EDR o habilitar Defender mediante politica.' 'Microsoft Defender Antivirus' $defender}
    if($defender.AntivirusSignatureLastUpdated -and ((Get-Date)-$defender.AntivirusSignatureLastUpdated).TotalDays -gt 3){Add-Finding 'AV-002' 'Alta' 'Antimalware' 'Firmas antimalware desactualizadas' ("Ultima actualizacion: {0}" -f $defender.AntivirusSignatureLastUpdated) 'Disminuye la deteccion de amenazas recientes.' 'Restablecer la fuente de inteligencia y actualizar firmas.' 'Microsoft Defender Antivirus' $defender}
}else{Add-Finding 'AV-003' 'Media' 'Antimalware' 'Estado de Microsoft Defender no disponible' 'Get-MpComputerStatus no devolvio datos.' 'No se confirma cobertura antimalware/EDR.' 'Verificar el agente EDR corporativo y su telemetria.' 'Microsoft Defender for Endpoint' $null}

$uac=Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
$lsa=Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$wdigest=Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
$scriptLogging=Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
$securityControls=[pscustomobject]@{UAC=$uac;LSAProtection=$lsa;WDigestUseLogonCredential=$wdigest;PowerShellScriptBlockLogging=$scriptLogging}
Add-ReportSection 'Credenciales y registro' 'UAC, LSA Protection, WDigest y registro de PowerShell.' $securityControls
if($uac -ne 1){Add-Finding 'UAC-001' 'Alta' 'Credenciales' 'UAC no habilitado' "EnableLUA=$uac" 'Facilita elevacion administrativa sin controles esperados.' 'Habilitar UAC mediante politica y validar aplicaciones.' 'Microsoft Security Baseline' $securityControls}
if($wdigest -eq 1){Add-Finding 'CRED-001' 'Critica' 'Credenciales' 'WDigest almacena credenciales reutilizables' 'UseLogonCredential=1' 'Puede exponer credenciales en memoria.' 'Deshabilitar mediante GPO y reiniciar en ventana controlada.' 'Microsoft Security Baseline' $securityControls}
if($lsa -notin 1,2){Add-Finding 'CRED-002' 'Media' 'Credenciales' 'Proteccion de LSA no confirmada' "RunAsPPL=$lsa" 'LSASS tiene menor aislamiento.' 'Evaluar y habilitar LSA Protection.' 'Microsoft LSA protection guidance' $securityControls}
if($scriptLogging -ne 1){Add-Finding 'LOG-001' 'Media' 'Registro' 'Script Block Logging no confirmado' "EnableScriptBlockLogging=$scriptLogging" 'Reduce visibilidad forense.' 'Habilitar Script Block Logging y centralizar eventos.' 'Microsoft PowerShell logging guidance' $securityControls}

$tlsRows=@()
foreach($proto in 'TLS 1.0','TLS 1.1','TLS 1.2'){
    $serverPath="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
    $clientPath="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Client"
    $row=[pscustomobject]@{Protocolo=$proto;ServerEnabled=(Get-RegValue $serverPath 'Enabled');ServerDisabledByDefault=(Get-RegValue $serverPath 'DisabledByDefault');ClientEnabled=(Get-RegValue $clientPath 'Enabled');ClientDisabledByDefault=(Get-RegValue $clientPath 'DisabledByDefault')}
    $tlsRows+=$row
    if($proto -in 'TLS 1.0','TLS 1.1' -and ($row.ServerEnabled -ne 0 -or $row.ServerDisabledByDefault -ne 1)){Add-Finding ("TLS-{0}" -f ($proto -replace '\D','')) 'Media' 'TLS' "$proto no esta deshabilitado explicitamente en servidor" ("Enabled={0}; DisabledByDefault={1}" -f $row.ServerEnabled,$row.ServerDisabledByDefault) 'Permite protocolos heredados.' 'Inventariar dependencias y deshabilitar cliente y servidor.' 'Microsoft TLS registry guidance' $row}
}
Add-ReportSection 'TLS/SCHANNEL' 'Configuracion explicita de TLS 1.0, 1.1 y 1.2.' $tlsRows

$admins=@(Invoke-SafeCheck 'Administradores locales' { Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name,ObjectClass,PrincipalSource,SID })
Add-ReportSection 'Administradores locales' 'Miembros del grupo Administrators.' $admins
if($admins.Count -gt 5){Add-Finding 'IAM-001' 'Media' 'Privilegios' 'Grupo Administradores local amplio' ("Miembros: {0}" -f $admins.Count) 'Aumenta la superficie de privilegio.' 'Revisar necesidad, usar grupos administrados, JIT/JEA y Windows LAPS.' 'Microsoft privileged access strategy' $admins}
$guest=Invoke-SafeCheck 'Cuenta invitado' { Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'" -ErrorAction Stop | Select-Object Name,Disabled,Lockout,SID }
Add-ReportSection 'Cuenta Invitado' 'Estado de la cuenta local con RID 501.' $guest
if($guest -and -not $guest.Disabled){Add-Finding 'IAM-002' 'Alta' 'Identidad' 'Cuenta Invitado habilitada' $guest.Name 'Agrega una via de acceso poco atribuible.' 'Deshabilitar mediante politica tras validar dependencias.' 'Microsoft Security Baseline' $guest}

$services=@(Invoke-SafeCheck 'Servicios' { Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,StartName,PathName })
Add-ReportSection 'Servicios' 'Inventario de servicios y cuentas de ejecucion.' $services
$badServices=@($services | Where-Object {$_.StartName -eq 'LocalSystem' -and $_.PathName -match '^\s*[^\"]*\s+[^\"]*\.exe'})
if($badServices.Count -gt 0){Add-Finding 'SVC-001' 'Alta' 'Servicios' 'Servicios privilegiados con posible ruta sin comillas' ("Detectados: {0}" -f $badServices.Count) 'Una ruta vulnerable con ACL debiles puede permitir elevacion.' 'Validar ImagePath y ACL antes de corregir.' 'Windows service path hardening' $badServices}

$auditText=Invoke-SafeCheck 'AuditPol' { (auditpol.exe /get /category:* /r 2>$null) -join "`n" }
$auditRows=@()
if($auditText){$lines=$auditText -split "`r?`n";foreach($line in $lines){if(-not [string]::IsNullOrWhiteSpace($line)){$auditRows+=[pscustomobject]@{Linea=$line}}}}
Add-ReportSection 'Politica de auditoria' 'Salida de auditpol /get /category:* /r.' $auditRows
if(-not $auditText){Add-Finding 'AUD-001' 'Media' 'Auditoria' 'No se pudo leer la politica de auditoria' 'auditpol no devolvio datos.' 'No se confirma trazabilidad.' 'Revisar Advanced Audit Policy y reenvio centralizado.' 'Microsoft advanced audit policy' $null}

$secureBoot=Invoke-SafeCheck 'Secure Boot' { Confirm-SecureBootUEFI -ErrorAction Stop }
Add-ReportSection 'Secure Boot' 'Estado informado por Confirm-SecureBootUEFI.' ([pscustomobject]@{SecureBoot=$secureBoot})
if($secureBoot -eq $false){Add-Finding 'BOOT-001' 'Media' 'Arranque' 'Secure Boot deshabilitado' 'Confirm-SecureBootUEFI=False' 'Reduce proteccion frente a bootkits.' 'Validar UEFI y habilitar en una ventana aprobada.' 'Microsoft Secure Boot' ([pscustomobject]@{SecureBoot=$secureBoot})}

$bitlocker=@(Invoke-SafeCheck 'BitLocker' { Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage })
Add-ReportSection 'BitLocker' 'Estado de cifrado de volumen.' $bitlocker
$bitlockerOff=@($bitlocker | Where-Object ProtectionStatus -eq 'Off')
if($bitlockerOff.Count -gt 0){Add-Finding 'ENC-001' 'Media' 'Cifrado' 'Volumen con proteccion BitLocker desactivada' (($bitlockerOff.MountPoint)-join ', ') 'El acceso fisico puede exponer datos.' 'Evaluar BitLocker y custodia de claves.' 'Microsoft BitLocker' $bitlockerOff}

$certs=@(Invoke-SafeCheck 'Certificados' { Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | Select-Object Subject,Issuer,Thumbprint,NotBefore,NotAfter,HasPrivateKey })
Add-ReportSection 'Certificados de equipo' 'Certificados en LocalMachine\My.' $certs
$expired=@($certs | Where-Object NotAfter -lt (Get-Date))
$soon=@($certs | Where-Object {$_.NotAfter -ge (Get-Date) -and $_.NotAfter -lt (Get-Date).AddDays(30)})
if($expired.Count -gt 0){Add-Finding 'CERT-001' 'Alta' 'Certificados' 'Certificados de equipo vencidos' ("Cantidad: {0}" -f $expired.Count) 'Puede causar fallas o uso de certificados obsoletos.' 'Confirmar uso, renovar o retirar mediante PKI.' 'Microsoft certificate lifecycle guidance' $expired}
if($soon.Count -gt 0){Add-Finding 'CERT-002' 'Media' 'Certificados' 'Certificados por vencer en 30 dias' ("Cantidad: {0}" -f $soon.Count) 'Riesgo de indisponibilidad.' 'Asignar propietario, renovar y validar cadena.' 'Microsoft certificate lifecycle guidance' $soon}

if($script:Errors.Count -gt 0){Add-ReportSection 'Errores de recoleccion' 'Comprobaciones que no pudieron completarse.' $script:Errors}

# Exportar evidencias y hallazgos antes del HTML
$script:Findings | Select-Object Id,Severidad,Categoria,Hallazgo,Evidencia,Riesgo,Recomendacion,Referencia,Cantidad | Export-Csv (Join-Path $OutputPath 'Hallazgos.csv') -NoTypeInformation -Encoding UTF8
foreach($section in $script:Sections){
    if($section.Datos.Count -gt 0){
        $safeName=($section.Nombre -replace '[^a-zA-Z0-9_-]','-').Trim('-')
        $section.Datos | Export-Csv (Join-Path $OutputPath ("Evidencia-{0}.csv" -f $safeName)) -NoTypeInformation -Encoding UTF8
    }
}

# -----------------------------------------------------------------------------
# Reporte HTML
# -----------------------------------------------------------------------------
function New-ServerSecurityReport {
    param(
        [object[]]$Findings,
        [object[]]$Sections,
        [object]$SystemInfo,
        [string]$Path
    )
    $sevOrder=@{Critica=0;Alta=1;Media=2;Baja=3;Informativa=4}
    $weights=@{Critica=10;Alta=6;Media=3;Baja=1;Informativa=0}
    $colors=@{Critica='#8b0000';Alta='#c62828';Media='#ef6c00';Baja='#2e7d32';Informativa='#455a64'}
    $sorted=@($Findings | Sort-Object {$sevOrder[$_.Severidad]},Categoria,Id)
    $counts=@{};foreach($s in $sevOrder.Keys){$counts[$s]=@($sorted | Where-Object Severidad -eq $s).Count}
    $raw=0;foreach($f in $sorted){$raw+=$weights[$f.Severidad]}
    $score=[math]::Min(100,$raw)
    $level=if($score -ge 50){'Critico'}elseif($score -ge 30){'Alto'}elseif($score -ge 15){'Medio'}else{'Bajo'}
    $levelColor=if($level -eq 'Critico'){$colors.Critica}elseif($level -eq 'Alto'){$colors.Alta}elseif($level -eq 'Medio'){$colors.Media}else{'#2e7d32'}

    $findingsHtml=New-Object System.Text.StringBuilder
    if($sorted.Count -eq 0){[void]$findingsHtml.Append('<p class="empty">No se detectaron hallazgos. Revise el anexo tecnico.</p>')}
    for($i=0;$i -lt $sorted.Count;$i++){
        $f=$sorted[$i]
        $detailTable=Convert-ObjectsToHtmlTable -Data $f.Datos -MaxRows 500
        [void]$findingsHtml.Append(@"
<details class="finding" data-sev="$($f.Severidad)" data-search="$(ConvertTo-HtmlText ($f.Id+' '+$f.Categoria+' '+$f.Hallazgo))">
<summary><span class="pill $($f.Severidad)">$($f.Severidad)</span><span class="fid">$(ConvertTo-HtmlText $f.Id)</span><strong>$(ConvertTo-HtmlText $f.Hallazgo)</strong><span class="count">$($f.Cantidad)</span></summary>
<div class="finding-body"><div class="meta"><p><b>Categoria:</b> $(ConvertTo-HtmlText $f.Categoria)</p><p><b>Evidencia:</b> $(ConvertTo-HtmlText $f.Evidencia)</p><p><b>Riesgo:</b> $(ConvertTo-HtmlText $f.Riesgo)</p><p><b>Recomendacion:</b> $(ConvertTo-HtmlText $f.Recomendacion)</p><p><b>Referencia:</b> $(ConvertTo-HtmlText $f.Referencia)</p></div>$detailTable</div>
</details>
"@)}

    $sectionsHtml=New-Object System.Text.StringBuilder
    foreach($section in $Sections){
        $table=Convert-ObjectsToHtmlTable -Data $section.Datos -MaxRows 1000
        [void]$sectionsHtml.Append(@"
<details class="section" open><summary><strong>$(ConvertTo-HtmlText $section.Nombre)</strong><span class="count">$($section.Cantidad)</span></summary>
<div class="section-body"><p class="note">$(ConvertTo-HtmlText $section.Descripcion)</p>$table</div></details>
"@)}

    $css=@'
:root{--ink:#17202a;--muted:#5f6b76;--line:#d9e0e7;--bg:#f4f6f8;--card:#fff}
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--ink)}
header{background:linear-gradient(135deg,#172b4d,#2457a6);color:#fff;padding:32px 24px}.wrap{max-width:1450px;margin:auto}header h1{margin:0 0 8px}.subtitle{opacity:.9}
nav{position:sticky;top:0;z-index:10;background:#fff;border-bottom:1px solid var(--line);padding:10px 24px}nav a{margin-right:16px;color:#2457a6;text-decoration:none;font-weight:600}
main{padding:22px 24px 50px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card{background:#fff;border-radius:10px;padding:16px;box-shadow:0 1px 5px #ccd}.card .n{font-size:29px;font-weight:700}
.banner{border-left:6px solid;padding:16px;background:#fff;border-radius:8px;margin:18px 0}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.toolbar input{padding:9px 12px;min-width:280px;border:1px solid var(--line);border-radius:8px}.toolbar button{padding:8px 13px;border:1px solid var(--line);border-radius:999px;background:#fff;cursor:pointer}.toolbar button.active{background:#172b4d;color:#fff}
details{background:#fff;margin:9px 0;border:1px solid var(--line);border-radius:8px;overflow:hidden}summary{cursor:pointer;padding:12px 14px;display:flex;gap:12px;align-items:center;list-style:none}summary::-webkit-details-marker{display:none}.finding summary strong{flex:1}.fid{font-family:Consolas,monospace;color:var(--muted)}.count{margin-left:auto;background:#eef2f7;border-radius:999px;padding:2px 9px}.finding-body,.section-body{padding:12px 14px;border-top:1px solid var(--line)}
.pill{padding:3px 8px;border-radius:999px;color:#fff;font-size:12px}.Critica{background:#8b0000}.Alta{background:#c62828}.Media{background:#ef6c00}.Baja{background:#2e7d32}.Informativa{background:#455a64}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:5px 20px}.meta p{margin:4px 0}
.table-scroll{overflow:auto;max-height:520px;border:1px solid var(--line);border-radius:6px}table{border-collapse:collapse;width:100%;font-size:12.5px;background:#fff}th,td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}th{position:sticky;top:0;background:#e9eef5;z-index:1;white-space:nowrap}tr:nth-child(even){background:#fafbfc}.note{color:var(--muted);font-size:13px}.empty{padding:15px;color:var(--muted);font-style:italic}
@media print{nav,.toolbar{display:none}.table-scroll{max-height:none;overflow:visible}details{break-inside:avoid}th{position:static}}
'@

    $html=@"
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Auditoria de seguridad - $(ConvertTo-HtmlText $SystemInfo.Equipo)</title><style>$css</style></head>
<body><header><div class="wrap"><h1>Auditoria de seguridad de Windows Server</h1><div class="subtitle">Equipo: <b>$(ConvertTo-HtmlText $SystemInfo.Equipo)</b> | SO: $(ConvertTo-HtmlText $SystemInfo.SistemaOperativo) | Generado: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))</div></div></header>
<nav><div class="wrap"><a href="#resumen">Resumen</a><a href="#hallazgos">Hallazgos</a><a href="#evidencia">Anexo tecnico</a></div></nav>
<main class="wrap"><section id="resumen"><div class="banner" style="border-color:$levelColor"><b>Evaluacion de solo lectura.</b> No se aplicaron cambios. Riesgo global: <b>$level</b>.</div>
<div class="cards"><div class="card"><div>Riesgo</div><div class="n" style="color:$levelColor">$level</div><small>$score/100</small></div><div class="card"><div>Criticas</div><div class="n">$($counts['Critica'])</div></div><div class="card"><div>Altas</div><div class="n">$($counts['Alta'])</div></div><div class="card"><div>Medias</div><div class="n">$($counts['Media'])</div></div><div class="card"><div>Secciones tecnicas</div><div class="n">$($Sections.Count)</div></div><div class="card"><div>Duracion</div><div class="n">$([math]::Round(((Get-Date)-$script:StartTime).TotalSeconds)) s</div></div></div></section>
<section id="hallazgos"><h2>Hallazgos y recomendaciones</h2><div class="toolbar"><input id="search" type="search" placeholder="Buscar hallazgo..."><button class="active" data-sev="all">Todos</button><button data-sev="Critica">Critica</button><button data-sev="Alta">Alta</button><button data-sev="Media">Media</button><button data-sev="Baja">Baja</button><button data-sev="Informativa">Informativa</button></div>$($findingsHtml.ToString())</section>
<section id="evidencia"><h2>Anexo tecnico</h2><p class="note">Las tablas se construyen directamente desde las propiedades de los objetos PowerShell recolectados.</p>$($sectionsHtml.ToString())</section>
</main><script>
(function(){var sev='all',q='';var items=[].slice.call(document.querySelectorAll('.finding'));function apply(){items.forEach(function(x){var ok=(sev==='all'||x.dataset.sev===sev)&&(!q||x.dataset.search.toLowerCase().indexOf(q)>=0);x.hidden=!ok;});}document.getElementById('search').addEventListener('input',function(){q=this.value.toLowerCase().trim();apply();});document.querySelectorAll('[data-sev]').forEach(function(b){b.addEventListener('click',function(){sev=b.dataset.sev;document.querySelectorAll('[data-sev]').forEach(function(z){z.classList.toggle('active',z===b);});apply();});});})();
</script></body></html>
"@
    if ([string]::IsNullOrWhiteSpace($html)) {
        throw 'La funcion de reporte produjo HTML vacio.'
    }

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    }

    $tempPath = Join-Path $parent ('Resumen-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($tempPath, $html, $utf8Bom)

    if (-not (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
        throw "No se pudo crear el archivo temporal del reporte: $tempPath"
    }
    if ((Get-Item -LiteralPath $tempPath -ErrorAction Stop).Length -lt 500) {
        throw "El HTML generado es demasiado pequeno y se considero invalido: $tempPath"
    }

    Move-Item -LiteralPath $tempPath -Destination $Path -Force -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "No se encontro el reporte despues de escribirlo: $Path"
    }
    return (Get-Item -LiteralPath $Path -ErrorAction Stop)
}

$reportPath = Join-Path $OutputPath 'Resumen.html'
$diagnosticPath = Join-Path $OutputPath 'Diagnostico.txt'
$reportFile = $null
$reportError = $null

try {
    $findingArray = @($script:Findings | ForEach-Object { $_ })
    $sectionArray = @($script:Sections | ForEach-Object { $_ })
    $reportFile = New-ServerSecurityReport -Findings $findingArray -Sections $sectionArray -SystemInfo $systemInfo -Path $reportPath
}
catch {
    $reportError = $_
    Add-AuditError 'Generacion del reporte HTML' $_.Exception.Message
}

$diagnosticLines = @(
    "Equipo: $env:COMPUTERNAME"
    "Hallazgos: $($script:Findings.Count)"
    "Secciones: $($script:Sections.Count)"
    "Errores de recoleccion: $($script:Errors.Count)"
    "Ruta esperada: $reportPath"
    "Reporte existe: $(Test-Path -LiteralPath $reportPath -PathType Leaf)"
)
if ($reportFile) {
    $diagnosticLines += "Tamano HTML: $($reportFile.Length) bytes"
} else {
    $diagnosticLines += "ERROR HTML: $($reportError.Exception.Message)"
    $diagnosticLines += "Detalle: $($reportError | Out-String)"
}
$diagnosticLines | Out-File -FilePath $diagnosticPath -Encoding UTF8 -Force

Write-Host ''
if ($reportFile -and (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
    Write-Host "Auditoria completada: $OutputPath" -ForegroundColor Green
    Write-Host "Reporte HTML creado: $reportPath" -ForegroundColor Green
    Write-Host "Tamano HTML: $($reportFile.Length) bytes" -ForegroundColor Green
    Write-Host "Hallazgos: $($script:Findings.Count) | Secciones: $($script:Sections.Count) | Errores: $($script:Errors.Count)"
}
else {
    Write-Host "ERROR: no fue posible crear Resumen.html" -ForegroundColor Red
    Write-Host "Detalle: $($reportError.Exception.Message)" -ForegroundColor Red
    Write-Host "Diagnostico: $diagnosticPath" -ForegroundColor Yellow
    exit 1
}
