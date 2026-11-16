<#
.SYNOPSIS
  Netzwerk-Scanner ohne nmap: Ping-Sweep, ARP, Hostnamen, NetBIOS, Portscan, Banner
  und Vergleich mit dem letzten Scan (merkt sich, was erreichbar war).

.DESCRIPTION
  Ablauf:
    1. Ping-Sweep ueber den Bereich (parallel)
    2. ARP-Tabelle auswerten (findet auch Geraete, die Ping blockieren)
    3. Infos sammeln: DNS-Name, NetBIOS-Name/Arbeitsgruppe, MAC, Hersteller, OS-Schaetzung (TTL)
    4. Portscan auf allen erreichbaren Geraeten
    5. Banner/Infos von offenen Ports holen (SSH-Version, HTTP-Server/Titel, TLS-Zertifikat ...)
    6. Ergebnis mit State-Datei vergleichen (neue Geraete, verschwundene, neue/geschlossene Ports)
       und State-Datei aktualisieren

.PARAMETER Range
  CIDR (192.168.1.0/24) oder Bereich (192.168.1.10-192.168.1.50). Leer = eigenes Netz.
.PARAMETER PingTimeout
  Ping-Timeout in ms (Standard 300).
.PARAMETER PingBatch
  Gleichzeitige Pings (Standard 256).
.PARAMETER Ports
  Komma-Liste, Bereiche und Schluesselwoerter: "common", "all", "22,80,443", "1-1024", "common,8000-8100".
.PARAMETER PortTimeout
  Verbindungs-Timeout pro Port in ms (Standard 500).
.PARAMETER PortBatch
  Gleichzeitige Port-Verbindungen pro Host (Standard 200).
.PARAMETER NoPortScan
  Keinen Portscan durchfuehren.
.PARAMETER NoBanner
  Keine Banner/Infos von offenen Ports holen.
.PARAMETER BannerTimeout
  Timeout fuer Banner-Abfragen in ms (Standard 1500).
.PARAMETER NoArp
  ARP-Tabelle nicht auswerten (nur Ping-Antworten zaehlen).
.PARAMETER NoDns
  Keine DNS-Namensaufloesung.
.PARAMETER NoNetBios
  Keine NetBIOS-Abfrage.
.PARAMETER NetBiosTimeout
  Timeout fuer NetBIOS-Abfragen in ms (Standard 1000).
.PARAMETER OuiFile
  Pfad zur IEEE-Herstellerliste (oui.txt) fuer MAC-Hersteller.
  Download: curl -L -o oui.txt https://standards-oui.ieee.org/oui/oui.txt
.PARAMETER StateFile
  Datei, in der sich das Skript die Ergebnisse merkt (Standard: scan_state.json neben dem Skript).
.PARAMETER NoState
  State-Datei weder lesen noch schreiben.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scan.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scan.ps1 -Range 192.168.1.0/24 -Ports common,8000-8100
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scan.ps1 -Range 10.0.0.1-10.0.0.50 -Ports all -PortTimeout 300
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scan.ps1 -NoPortScan
#>
[CmdletBinding()]
param(
    [string]$Range,
    [ValidateRange(50, 10000)] [int]$PingTimeout = 300,
    [ValidateRange(1, 2048)]   [int]$PingBatch = 256,
    [string]$Ports = 'common',
    [ValidateRange(50, 10000)] [int]$PortTimeout = 500,
    [ValidateRange(1, 2048)]   [int]$PortBatch = 200,
    [switch]$NoPortScan,
    [switch]$NoBanner,
    [ValidateRange(100, 20000)] [int]$BannerTimeout = 1500,
    [switch]$NoArp,
    [switch]$NoDns,
    [switch]$NoNetBios,
    [ValidateRange(100, 10000)] [int]$NetBiosTimeout = 1000,
    [string]$OuiFile,
    [string]$StateFile,
    [switch]$NoState
)

$ErrorActionPreference = 'Continue'
$startTime = Get-Date
$now = $startTime.ToString('yyyy-MM-dd HH:mm:ss')

if (-not $StateFile) {
    $dir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $StateFile = Join-Path $dir 'scan_state.json'
}

# ============================================================================
#  Konstanten
# ============================================================================
$CommonPorts = @(21,22,23,25,53,80,81,88,110,111,135,139,143,161,389,443,445,465,515,548,
                 554,587,631,636,993,995,1433,1521,1723,1883,2049,3000,3306,3389,5000,5060,
                 5432,5900,5985,5986,6379,8000,8008,8080,8081,8443,8888,9000,9100,9200,27017)

$ServiceNames = @{
    21='ftp'; 22='ssh'; 23='telnet'; 25='smtp'; 53='dns'; 80='http'; 81='http-alt'; 88='kerberos'
    110='pop3'; 111='rpcbind'; 135='msrpc'; 139='netbios'; 143='imap'; 161='snmp'; 389='ldap'
    443='https'; 445='smb'; 465='smtps'; 515='lpd'; 548='afp'; 554='rtsp'; 587='submission'
    631='ipp'; 636='ldaps'; 993='imaps'; 995='pop3s'; 1433='mssql'; 1521='oracle'; 1723='pptp'
    1883='mqtt'; 2049='nfs'; 3000='http-dev'; 3306='mysql'; 3389='rdp'; 5000='http/upnp'
    5060='sip'; 5432='postgres'; 5900='vnc'; 5985='winrm'; 5986='winrm-tls'; 6379='redis'
    8000='http-alt'; 8008='http-alt'; 8080='http-proxy'; 8081='http-alt'; 8443='https-alt'
    8888='http-alt'; 9000='http-alt'; 9100='jetdirect'; 9200='elasticsearch'; 27017='mongodb'
}
$HttpPorts = @(80,81,3000,5000,5985,8000,8008,8080,8081,8888,9000,9200)
$TlsPorts  = @(443,465,636,993,995,5986,8443)
$HttpsPorts = @(443,8443,5986)

# ============================================================================
#  Hilfsfunktionen
# ============================================================================
function ConvertTo-UInt32([string]$ip) {
    $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($b)
    [BitConverter]::ToUInt32($b, 0)
}

function ConvertTo-IP([uint32]$n) {
    $b = [BitConverter]::GetBytes($n)
    [Array]::Reverse($b)
    [Net.IPAddress]::new($b).ToString()
}

function Get-PortList([string]$spec) {
    $set = New-Object 'System.Collections.Generic.SortedSet[int]'
    foreach ($part in ($spec -split ',')) {
        $p = $part.Trim().ToLower()
        if (-not $p) { continue }
        if ($p -eq 'common') { foreach ($x in $CommonPorts) { [void]$set.Add($x) } }
        elseif ($p -eq 'all') { for ($i = 1; $i -le 65535; $i++) { [void]$set.Add($i) } }
        elseif ($p -match '^(\d+)-(\d+)$') {
            $a = [int]$Matches[1]; $b = [int]$Matches[2]
            if ($a -gt $b) { $a, $b = $b, $a }
            for ($i = [math]::Max(1, $a); $i -le [math]::Min(65535, $b); $i++) { [void]$set.Add($i) }
        }
        elseif ($p -match '^\d+$' -and [int]$p -ge 1 -and [int]$p -le 65535) { [void]$set.Add([int]$p) }
        else { throw "Ungueltige Portangabe: '$part'" }
    }
    return @($set)
}

function Get-OsGuess($ttl) {
    if (-not $ttl) { return '' }
    if ($ttl -le 64)  { return "vermutlich Linux/Unix/macOS/Android (TTL $ttl)" }
    if ($ttl -le 128) { return "vermutlich Windows (TTL $ttl)" }
    return "vermutlich Netzwerkgeraet/Router/Drucker (TTL $ttl)"
}

function Get-Vendor([string]$mac) {
    if (-not $mac) { return '' }
    $m = $mac.ToUpper().Replace(':', '-')
    $first = [Convert]::ToInt32($m.Substring(0, 2), 16)
    if ($first -band 2) { return '(zufaellige/lokale MAC)' }
    $v = $script:Oui[$m.Substring(0, 8)]
    if ($v) { return $v } else { return '' }
}

function Get-ServiceName([int]$port) {
    $s = $ServiceNames[$port]
    if ($s) { return $s } else { return '?' }
}

function Read-FromStream($stream, [int]$max, [switch]$Once) {
    $buf = New-Object byte[] $max
    $total = 0
    try {
        do {
            $n = $stream.Read($buf, $total, $max - $total)
            if ($n -gt 0) { $total += $n }
        } while ($n -gt 0 -and $total -lt $max -and -not $Once)
    } catch {}
    return [Text.Encoding]::ASCII.GetString($buf, 0, $total)
}

function Format-HttpResponse([string]$resp) {
    $parts = @()
    if ($resp -match '^HTTP/\S+\s+(\d{3})') { $parts += "HTTP $($Matches[1])" }
    if ($resp -match '(?im)^Server:\s*(.+?)\r?$') { $parts += "Server: $($Matches[1].Trim())" }
    if ($resp -match '(?im)^Location:\s*(.+?)\r?$') { $parts += "-> $($Matches[1].Trim())" }
    if ($resp -match '(?is)<title[^>]*>\s*(.*?)\s*</title>') {
        $t = ($Matches[1] -replace '\s+', ' ')
        if ($t.Length -gt 60) { $t = $t.Substring(0, 60) + '...' }
        $parts += "Titel: $t"
    }
    return ($parts -join ' | ')
}

function Get-Banner([string]$ip, [int]$port, [int]$timeout) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($ip, $port).Wait($timeout)) { return '' }
        $client.ReceiveTimeout = $timeout
        $client.SendTimeout = $timeout
        $stream = $client.GetStream()
        $request = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: $ip`r`nUser-Agent: scan.ps1`r`nConnection: close`r`n`r`n")

        if ($TlsPorts -contains $port) {
            $cb = [Net.Security.RemoteCertificateValidationCallback] { $true }
            $ssl = New-Object Net.Security.SslStream($stream, $false, $cb)
            $ssl.ReadTimeout = $timeout
            $ssl.WriteTimeout = $timeout
            $ssl.AuthenticateAsClient($ip)
            $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $info = "TLS-Zertifikat: $($cert.Subject) (gueltig bis $($cert.NotAfter.ToString('yyyy-MM-dd')))"
            if ($HttpsPorts -contains $port) {
                $ssl.Write($request, 0, $request.Length)
                $http = Format-HttpResponse (Read-FromStream $ssl 8192)
                if ($http) { $info = "$http | $info" }
            }
            return $info
        }

        if ($HttpPorts -contains $port) {
            $stream.Write($request, 0, $request.Length)
            return (Format-HttpResponse (Read-FromStream $stream 8192))
        }

        # Andere Dienste: warten, ob der Server von sich aus etwas sendet (SSH, FTP, SMTP, ...)
        $text = Read-FromStream $stream 1024 -Once
        $line = ($text -split "`n")[0] -replace '[^\x20-\x7E]', '.'
        $line = $line.Trim()
        if ($line.Length -gt 100) { $line = $line.Substring(0, 100) + '...' }
        return $line
    } catch {
        return ''
    } finally {
        $client.Close()
    }
}

function Invoke-PortScan([string]$ip, [int[]]$portList, [int]$timeout, [int]$batch) {
    $open = New-Object 'System.Collections.Generic.List[int]'
    $addr = [Net.IPAddress]::Parse($ip)
    for ($o = 0; $o -lt $portList.Count; $o += $batch) {
        $last = [math]::Min($o + $batch, $portList.Count) - 1
        $jobs = foreach ($p in $portList[$o..$last]) {
            $c = New-Object Net.Sockets.TcpClient
            [pscustomobject]@{ Port = $p; Client = $c; Task = $c.ConnectAsync($addr, $p) }
        }
        try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($jobs.Task), $timeout) } catch {}
        foreach ($j in $jobs) {
            if ($j.Task.Status -eq 'RanToCompletion' -and $j.Client.Connected) { $open.Add($j.Port) }
            $j.Client.Close()
        }
        if ($portList.Count -gt $batch) {
            Write-Progress -Id 2 -ParentId 1 -Activity "Ports $ip" -Status "$($last + 1) / $($portList.Count)" `
                -PercentComplete ((($last + 1) / $portList.Count) * 100)
        }
    }
    Write-Progress -Id 2 -Activity "Ports $ip" -Completed
    return $open.ToArray()
}

function Get-NetBiosInfo([string[]]$ipList, [int]$timeout) {
    $result = @{}
    # NBSTAT-Abfrage auf Name "*"
    [byte[]]$query = @(0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20) +
                     [Text.Encoding]::ASCII.GetBytes('CK' + ('A' * 30)) +
                     @(0, 0, 0x21, 0, 1)
    $jobs = foreach ($ip in $ipList) {
        try {
            $u = New-Object Net.Sockets.UdpClient
            [void]$u.Send($query, $query.Length, $ip, 137)
            [pscustomobject]@{ IP = $ip; Udp = $u; Task = $u.ReceiveAsync() }
        } catch {}
    }
    if (-not $jobs) { return $result }
    try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($jobs.Task), $timeout) } catch {}
    foreach ($j in $jobs) {
        if ($j.Task.Status -eq 'RanToCompletion') {
            try {
                $d = $j.Task.Result.Buffer
                if ($d.Length -lt 57) { continue }
                $count = $d[56]
                $name = ''; $group = ''; $fileServer = $false
                for ($k = 0; $k -lt $count; $k++) {
                    $off = 57 + $k * 18
                    if ($off + 18 -gt $d.Length) { break }
                    $n = [Text.Encoding]::ASCII.GetString($d, $off, 15).TrimEnd(' ', [char]0)
                    $suffix = $d[$off + 15]
                    $isGroup = ($d[$off + 16] -band 0x80) -ne 0
                    if ($suffix -eq 0x00 -and -not $isGroup -and -not $name)  { $name = $n }
                    if ($suffix -eq 0x00 -and $isGroup -and -not $group)      { $group = $n }
                    if ($suffix -eq 0x20) { $fileServer = $true }
                }
                $result[$j.IP] = [pscustomobject]@{ Name = $name; Group = $group; FileServer = $fileServer }
            } catch {}
        }
        $j.Udp.Close()
    }
    return $result
}

# ============================================================================
#  Bereich bestimmen
# ============================================================================
if (-not $Range) {
    $cfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
           Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
           Select-Object -First 1
    if (-not $cfg) { Write-Host "Kein aktives Netz gefunden. Bitte -Range angeben." -ForegroundColor Red; exit 1 }
    $addr = $cfg.IPv4Address | Select-Object -First 1
    $Range = "$($addr.IPAddress)/$($addr.PrefixLength)"
    Write-Host "Erkanntes Netz: $Range"
}

if ($Range -match '^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$') {
    $pl = [int]$Matches[3]
    if ($pl -lt 16 -or $pl -gt 30) { Write-Host "Praefix muss zwischen /16 und /30 liegen." -ForegroundColor Red; exit 1 }
    $base  = ConvertTo-UInt32 $Matches[1]
    $size  = [uint32][math]::Pow(2, 32 - $pl)
    $mask  = [uint32]([math]::Pow(2, 32) - $size)
    $net   = [uint32]($base -band $mask)
    $start = [uint32]($net + 1)
    $end   = [uint32]($net + $size - 2)
}
elseif ($Range -match '^(\d{1,3}(\.\d{1,3}){3})-(\d{1,3}(\.\d{1,3}){3})$') {
    $start = ConvertTo-UInt32 $Matches[1]
    $end   = ConvertTo-UInt32 $Matches[3]
    if ($end -lt $start) { Write-Host "End-IP liegt vor Start-IP." -ForegroundColor Red; exit 1 }
    if (($end - $start) -ge 65534) { Write-Host "Bereich zu gross (max. 65534 Adressen)." -ForegroundColor Red; exit 1 }
}
elseif ($Range -match '^\d{1,3}(\.\d{1,3}){3}$') {
    $start = ConvertTo-UInt32 $Range
    $end = $start
}
else {
    Write-Host "Ungueltiges Format. Beispiele: 192.168.1.0/24, 192.168.1.10-192.168.1.50, 192.168.1.20" -ForegroundColor Red
    exit 1
}

try { $portList = @(Get-PortList $Ports) } catch { Write-Host $_ -ForegroundColor Red; exit 1 }
$portSet = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($p in $portList) { [void]$portSet.Add($p) }

# Herstellerliste laden
$script:Oui = @{}
if ($OuiFile) {
    if (Test-Path $OuiFile) {
        foreach ($line in [IO.File]::ReadLines((Resolve-Path $OuiFile).Path)) {
            if ($line -match '^\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$') {
                $script:Oui[$Matches[1].ToUpper()] = $Matches[2].Trim()
            }
        }
        Write-Host "Herstellerliste geladen: $($script:Oui.Count) Eintraege"
    } else {
        Write-Warning "OUI-Datei '$OuiFile' nicht gefunden - Hersteller werden nicht angezeigt."
    }
}

# State laden
$state = @{}
$lastScan = $null
if (-not $NoState -and (Test-Path $StateFile)) {
    try {
        $raw = Get-Content $StateFile -Raw | ConvertFrom-Json
        $lastScan = $raw.LastScan
        foreach ($prop in $raw.Hosts.PSObject.Properties) {
            $h = $prop.Value
            $state[$prop.Name] = [ordered]@{
                MAC          = $h.MAC
                Hostname     = $h.Hostname
                NetBios      = $h.NetBios
                FirstSeen    = $h.FirstSeen
                LastSeen     = $h.LastSeen
                OpenPorts    = [int[]]@($h.OpenPorts | Where-Object { $_ -ne $null } | ForEach-Object { [int]$_ })
                PortsScanned = [bool]$h.PortsScanned
            }
        }
        Write-Host "Letzter Scan: $lastScan ($($state.Count) bekannte Geraete)"
    } catch {
        Write-Warning "State-Datei '$StateFile' konnte nicht gelesen werden - es wird neu begonnen."
        $state = @{}
    }
}

$ips = @(for ([uint32]$i = $start; $i -le $end; $i++) { ConvertTo-IP $i })
Write-Host "Scanne $($ips.Count) Adresse(n): $(ConvertTo-IP $start) - $(ConvertTo-IP $end)"
if (-not $NoPortScan) { Write-Host "Ports: $($portList.Count) pro Geraet" }
Write-Host ""

# ============================================================================
#  1. Ping-Sweep
# ============================================================================
$pingInfo = @{}
for ($o = 0; $o -lt $ips.Count; $o += $PingBatch) {
    $last  = [math]::Min($o + $PingBatch, $ips.Count) - 1
    $jobs  = foreach ($ip in @($ips[$o..$last])) {
        [pscustomobject]@{ IP = $ip; Task = (New-Object Net.NetworkInformation.Ping).SendPingAsync($ip, $PingTimeout) }
    }
    try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($jobs.Task)) } catch {}
    foreach ($j in $jobs) {
        if ($j.Task.Status -eq 'RanToCompletion' -and $j.Task.Result.Status -eq 'Success') {
            $r = $j.Task.Result
            $ttl = $null
            if ($r.Options) { $ttl = $r.Options.Ttl }
            $pingInfo[$j.IP] = [pscustomobject]@{ Ttl = $ttl; Rtt = $r.RoundtripTime }
        }
    }
    Write-Progress -Id 1 -Activity "Ping-Sweep" -Status "$($last + 1) / $($ips.Count)" -PercentComplete ((($last + 1) / $ips.Count) * 100)
}
Write-Progress -Id 1 -Activity "Ping-Sweep" -Completed

# ============================================================================
#  2. ARP-Tabelle
# ============================================================================
$neigh = @{}
if (-not $NoArp) {
    try {
        Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.State -notin 'Unreachable', 'Incomplete' -and $_.LinkLayerAddress -and
                           $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF' } |
            ForEach-Object { $neigh[$_.IPAddress] = $_.LinkLayerAddress.ToUpper() }
    } catch {
        arp -a | ForEach-Object {
            if ($_ -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})') {
                if ($Matches[2] -ne 'ff-ff-ff-ff-ff-ff') { $neigh[$Matches[1]] = $Matches[2].ToUpper() }
            }
        }
    }
}

$found = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($ip in $pingInfo.Keys) { [void]$found.Add($ip) }
foreach ($ip in $neigh.Keys) {
    try { $n = ConvertTo-UInt32 $ip } catch { continue }
    if ($n -ge $start -and $n -le $end) { [void]$found.Add($ip) }
}
$foundList = @($found | Sort-Object { ConvertTo-UInt32 $_ })
Write-Host "$($foundList.Count) erreichbare(s) Geraet(e) gefunden."

# ============================================================================
#  3. Infos sammeln: DNS + NetBIOS
# ============================================================================
$dnsNames = @{}
if (-not $NoDns -and $foundList.Count -gt 0) {
    Write-Host "Loese Hostnamen auf ..."
    $dnsJobs = foreach ($ip in $foundList) { [pscustomobject]@{ IP = $ip; Task = [Net.Dns]::GetHostEntryAsync($ip) } }
    try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($dnsJobs.Task), 3000) } catch {}
    foreach ($d in $dnsJobs) {
        if ($d.Task.Status -eq 'RanToCompletion' -and $d.Task.Result.HostName -ne $d.IP) { $dnsNames[$d.IP] = $d.Task.Result.HostName }
    }
}

$nbInfo = @{}
if (-not $NoNetBios -and $foundList.Count -gt 0) {
    Write-Host "Frage NetBIOS-Namen ab ..."
    $nbInfo = Get-NetBiosInfo $foundList $NetBiosTimeout
}

# ============================================================================
#  4. + 5. Portscan und Banner
# ============================================================================
$results = New-Object System.Collections.Generic.List[object]
$idx = 0
foreach ($ip in $foundList) {
    $idx++
    $openPorts = @()
    $portDetails = [ordered]@{}
    if (-not $NoPortScan) {
        Write-Progress -Id 1 -Activity "Portscan" -Status "$ip ($idx / $($foundList.Count))" -PercentComplete (($idx / $foundList.Count) * 100)
        $openPorts = @(Invoke-PortScan $ip $portList $PortTimeout $PortBatch)
        foreach ($p in $openPorts) {
            $banner = ''
            if (-not $NoBanner) { $banner = Get-Banner $ip $p $BannerTimeout }
            $portDetails["$p"] = [pscustomobject]@{ Port = $p; Service = (Get-ServiceName $p); Info = $banner }
        }
    }

    $mac = $neigh[$ip]
    $nb  = $nbInfo[$ip]
    $pi  = $pingInfo[$ip]
    $results.Add([pscustomobject]@{
        IP        = $ip
        Status    = if ($state.ContainsKey($ip)) { 'bekannt' } else { 'NEU' }
        Hostname  = $dnsNames[$ip]
        NetBios   = if ($nb) { $nb.Name } else { '' }
        Gruppe    = if ($nb) { $nb.Group } else { '' }
        MAC       = $mac
        Hersteller= Get-Vendor $mac
        Ping      = [bool]$pi
        TTL       = if ($pi) { $pi.Ttl } else { $null }
        RTT_ms    = if ($pi) { $pi.Rtt } else { $null }
        OS        = if ($pi) { Get-OsGuess $pi.Ttl } else { '' }
        OpenPorts = [int[]]$openPorts
        Ports     = @($portDetails.Values)
    })
}
Write-Progress -Id 1 -Activity "Portscan" -Completed

# ============================================================================
#  6. Vergleich mit letztem Scan
# ============================================================================
$changes = New-Object System.Collections.Generic.List[string]
if (-not $NoState) {
    foreach ($r in $results) {
        $label = $r.IP
        $nm = @($r.Hostname, $r.NetBios) | Where-Object { $_ } | Select-Object -First 1
        if ($nm) { $label = "$($r.IP) ($nm)" }

        if (-not $state.ContainsKey($r.IP)) {
            $changes.Add("NEU: $label MAC=$($r.MAC)")
            continue
        }
        $old = $state[$r.IP]
        if ($old.MAC -and $r.MAC -and $old.MAC -ne $r.MAC) {
            $changes.Add("MAC GEAENDERT: $label $($old.MAC) -> $($r.MAC)")
        }
        if (-not $NoPortScan -and $old.PortsScanned) {
            $newOpen = @($r.OpenPorts | Where-Object { $old.OpenPorts -notcontains $_ })
            $closed  = @($old.OpenPorts | Where-Object { $portSet.Contains($_) -and $r.OpenPorts -notcontains $_ })
            if ($newOpen.Count) { $changes.Add("PORTS NEU OFFEN: $label -> $($newOpen -join ', ')") }
            if ($closed.Count)  { $changes.Add("PORTS GESCHLOSSEN: $label -> $($closed -join ', ')") }
        }
    }
    foreach ($ip in @($state.Keys)) {
        try { $n = ConvertTo-UInt32 $ip } catch { continue }
        if ($n -ge $start -and $n -le $end -and -not $found.Contains($ip)) {
            $nm = @($state[$ip].Hostname, $state[$ip].NetBios) | Where-Object { $_ } | Select-Object -First 1
            $label = if ($nm) { "$ip ($nm)" } else { $ip }
            $changes.Add("NICHT MEHR ERREICHBAR: $label (zuletzt gesehen $($state[$ip].LastSeen))")
        }
    }

    # State aktualisieren
    foreach ($r in $results) {
        $old = $state[$r.IP]
        $entry = [ordered]@{
            MAC          = if ($r.MAC) { $r.MAC } elseif ($old) { $old.MAC } else { '' }
            Hostname     = if ($r.Hostname) { $r.Hostname } elseif ($old) { $old.Hostname } else { '' }
            NetBios      = if ($r.NetBios) { $r.NetBios } elseif ($old) { $old.NetBios } else { '' }
            FirstSeen    = if ($old -and $old.FirstSeen) { $old.FirstSeen } else { $now }
            LastSeen     = $now
            OpenPorts    = [int[]]@()
            PortsScanned = $false
        }
        if (-not $NoPortScan) {
            # Ports, die diesmal nicht geprueft wurden, aus dem alten Stand behalten
            $keep = @()
            if ($old) { $keep = @($old.OpenPorts | Where-Object { -not $portSet.Contains($_) }) }
            $entry.OpenPorts = [int[]]@(@($keep) + @($r.OpenPorts) | Sort-Object -Unique)
            $entry.PortsScanned = $true
        } elseif ($old) {
            $entry.OpenPorts = [int[]]$old.OpenPorts
            $entry.PortsScanned = $old.PortsScanned
        }
        $state[$r.IP] = $entry
    }

    $sorted = [ordered]@{}
    foreach ($ip in ($state.Keys | Sort-Object { ConvertTo-UInt32 $_ })) { $sorted[$ip] = $state[$ip] }
    $out = [ordered]@{ LastScan = $now; LastRange = $Range; Hosts = $sorted }
    try {
        $out | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8
    } catch {
        Write-Warning "State-Datei konnte nicht geschrieben werden: $_"
    }
}

# ============================================================================
#  Ausgabe
# ============================================================================
Write-Host ""
Write-Host ("=" * 70)
foreach ($r in $results) {
    $color = if ($r.Status -eq 'NEU' -and -not $NoState -and $lastScan) { 'Yellow' } else { 'Cyan' }
    $tag = if ($r.Status -eq 'NEU' -and -not $NoState -and $lastScan) { '  [NEU]' } else { '' }
    Write-Host "$($r.IP)$tag" -ForegroundColor $color
    if ($r.Hostname) { Write-Host "  Hostname : $($r.Hostname)" }
    if ($r.NetBios)  {
        $g = if ($r.Gruppe) { " (Gruppe: $($r.Gruppe))" } else { '' }
        Write-Host "  NetBIOS  : $($r.NetBios)$g"
    }
    if ($r.MAC) {
        $v = if ($r.Hersteller) { "  $($r.Hersteller)" } else { '' }
        Write-Host "  MAC      : $($r.MAC)$v"
    }
    if ($r.Ping) {
        $os = if ($r.OS) { ", $($r.OS)" } else { '' }
        Write-Host "  Ping     : $($r.RTT_ms) ms$os"
    }
    else         { Write-Host "  Ping     : keine Antwort (nur ueber ARP gefunden)" }
    if (-not $NoPortScan) {
        if ($r.Ports.Count -eq 0) {
            Write-Host "  Ports    : keine offenen Ports gefunden"
        } else {
            $first = $true
            foreach ($p in $r.Ports) {
                $prefix = if ($first) { "  Ports    : " } else { "             " }
                $info = if ($p.Info) { "  $($p.Info)" } else { '' }
                Write-Host ("{0}{1,-6} {2,-14}{3}" -f $prefix, $p.Port, $p.Service, $info) -ForegroundColor Green
                $first = $false
            }
        }
    }
    Write-Host ""
}

if (-not $NoState) {
    Write-Host ("=" * 70)
    if (-not $lastScan) {
        Write-Host "Erster Scan - Ergebnisse gespeichert in $StateFile"
    } elseif ($changes.Count -eq 0) {
        Write-Host "Keine Aenderungen seit dem letzten Scan ($lastScan)." -ForegroundColor Green
    } else {
        Write-Host "Aenderungen seit dem letzten Scan ($lastScan):" -ForegroundColor Yellow
        foreach ($c in $changes) { Write-Host "  $c" -ForegroundColor Yellow }
    }
}


$dur = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Write-Host ""
Write-Host "Fertig in $dur s: $($results.Count) Geraet(e), $(@($results | ForEach-Object { $_.OpenPorts } ).Count) offene Port(s)."
