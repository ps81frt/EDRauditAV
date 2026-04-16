<#
.SYNOPSIS
    EDR- Diagnostic et Remédiation de la Sécurité Windows (Firewall, Defender, SmartScreen, LSA, SMBv1)
.DESCRIPTION
    Ce script PowerShell complet réalise un audit approfondi de la sécurité Windows, en vérifiant les configurations critiques telles que le Firewall, Windows Defender, SmartScreen, la protection LSA (RunAsPPL) et la vulnérabilité SMBv1. Il détecte également les antivirus tiers installés et leur état de protection. En cas de configuration non sécurisée, il propose des conseils dynamiques et peut appliquer des remédiations ciblées via le paramètre -Fix.    
.PARAMETER Fix
    Permet de réparer automatiquement les points de sécurité critiques détectés. Accepte les valeurs :  "Firewall", "SmartScreen", "Defender", "SMBv1", "LSA" ou "All" pour tout réparer. Par défaut, aucune action de réparation n'est effectuée.
.EXAMPLE
    .\EDRauditAV.ps1
    Réalise un audit complet de la sécurité Windows sans appliquer de remédiation.
.PARAMETER Help
    Affiche l'aide détaillée avec des exemples de commandes et des conseils de remédiation.
.NOTES
    Script créé pour l'audit et la remédiation de la sécurité Windows.
.AUTHOR
    ps81frt
.LINK
    https://github.com/ps81frt/EDRauditAV   
#>

param(
    [ValidateSet("All", "Firewall", "SmartScreen", "Defender", "SMBv1", "LSA", "None")]
    [string]$Fix = "None",
    [switch]$ShareDpaste,
    [switch]$ShareGofile,
    [switch]$Help
)

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and $Fix -ne "None") {
    Write-Host "`n  [ ACCÈS REFUSÉ ]" -ForegroundColor White -BackgroundColor Red
    Write-Host "   Erreur : Les privilèges Administrateur sont requis pour réparer : -Fix $Fix" -ForegroundColor Red
    Write-Host "   Conseil : Faites un clic droit sur PowerShell > 'Exécuter en tant qu'administrateur'." -ForegroundColor Gray
    exit
}

function Show-Banner {
    Clear-Host
    $banner = @"

                                    ███████╗██████╗ ██████╗ 
                                    ██╔════╝██╔══██╗██╔══██╗
                                    █████╗  ██║  ██║██████╔╝
                                    ██╔══╝  ██║  ██║██╔══██╗
                                    ███████╗██████╔╝██║  ██║
                                    ╚══════╝╚═════╝ ╚═╝  ╚═╝
"@
    Write-Host $banner -ForegroundColor Cyan
}
if ($Help) {

    Show-Banner

    Write-Host "`n                                        [ EDR - AIDE ]" -ForegroundColor Cyan
    Write-Host " ------------------------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " [ COMMANDE ]" -ForegroundColor White
    Write-Host "   .\EDRauditAV.ps1                 -> Audit (Lecture seule)" -ForegroundColor Gray
    Write-Host "   .\EDRauditAV.ps1 -Fix Firewall   -> Répare le Firewall" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix SmartScreen -> Répare SmartScreen" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix Defender    -> Répare Windows Defender" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix SMBv1       -> Répare SMBv1" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix LSA         -> Répare le LSA" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix All          -> RÉPARER TOUT" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " [ EXPORT & PARTAGE ]" -ForegroundColor White
    Write-Host ""
    Write-Host "   .\EDRauditAV.ps1 *> $env:USERPROFILE\Desktop\Rapport_EDR.txt   -> Export sur le Bureau" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   .\EDRauditAV.ps1 -ShareDpaste    -> Upload vers dpaste (Lecture Web directe)" -ForegroundColor Magenta
    Write-Host "   .\EDRauditAV.ps1 -ShareGofile    -> Upload vers Gofile (Téléchargement fichier)" -ForegroundColor Magenta
    Write-Host ""
    Write-Host " ------------------------------------------------------------------------------------------------" -ForegroundColor Cyan

    exit
}

& {
#----------------------------------------------------
#  START TRANSCRIPTION
#----------------------------------------------------
$PathBureau = "$env:USERPROFILE\Desktop\Rapport_EDR.txt"
if ($ShareDpaste -or $ShareGofile) {
    Start-Transcript -Path $PathBureau -Force -ErrorAction SilentlyContinue | Out-Null
}


Write-Host "`n================ DIAG SECURITE COMPLET =================" -ForegroundColor Cyan

function Invoke-SecurityFix {
    param([string]$Type)
    Write-Host "`n[!] Remédiation DFIR en cours pour : $Type..." -ForegroundColor Cyan
    
    switch ($Type) {
        "Firewall" { 
            Write-Host "Nettoyage des restrictions GPO et reset Firewall..." -ForegroundColor Gray
            Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -Recurse -ErrorAction SilentlyContinue
            netsh advfirewall set allprofiles state on; netsh advfirewall reset 
        }
        
        "SmartScreen" { 
            Write-Host "Suppression des blocages GPO et activation SmartScreen..." -ForegroundColor Gray
            $null = Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Force
        }

        "Defender" { 
            Write-Host "Réactivation forcée des moteurs Defender..." -ForegroundColor Gray
            Set-MpPreference -PUAProtection Enabled -RealTimeProtectionEnabled $true -DisableBlockAtFirstSeen $false
        }

        "SMBv1" { 
            Write-Host "Désactivation du protocole vulnérable (CVE-2017-0144)..." -ForegroundColor Gray
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        }

        "LSA" { 
            Write-Host "Application protection LSA (RunAsPPL)..." -ForegroundColor Gray
            Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force
        }
    }
    Write-Host "OK : Remédiation terminée." -ForegroundColor Green
}

#----------------------------------------------------
#  1. ANTIVIRUS (Security Center) 
#----------------------------------------------------

Write-Host "`n>>> Antivirus détectés (WMI / Security Center) :" -ForegroundColor Yellow

$avRaw = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct)

$avProducts = $avRaw | ForEach-Object {
    $stateHex = [System.Convert]::ToString($_.productState, 16).PadLeft(6, '0')
    
    # Détection de l'état (10 = Activé et à jour / 11 = Activé mais périmé)
    $status = if ($stateHex.Substring(2,2) -match "10|11") { "ACTIF" } else { "INACTIF/ALERTE" }
    
    [PSCustomObject]@{
        Nom       = $_.displayName
        Etat      = $status
        EtatBrut  = $_.productState
        state     = $status 
        displayName = $_.displayName
    }
} 

$avProducts | Select-Object Nom, Etat, EtatBrut | Format-Table -AutoSize
Write-Host "CONSEIL : Si ÉtatBrut ne commence pas par 39 (Defender) ou 26 (Tiers), vérifiez la licence." -ForegroundColor Gray

#----------------------------------------------------
#  2. WINDOWS DEFENDER DETAIL COMPLET 
#----------------------------------------------------
Write-Host "`n>>> Windows Defender (détail complet) :" -ForegroundColor Yellow

$avTiers = ($avProducts | Where-Object { $_.displayName -notlike "*Windows Defender*" }).displayName

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $excl = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath
    
    $sigAge = 0
    if ($mp.AntivirusSignatureLastUpdated) {
        $sigAge = (New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)).TotalHours
    }

    [PSCustomObject]@{
        "Moteur_Actif"        = $mp.AntivirusEnabled
        "Protection_TempsReel"= $mp.RealTimeProtectionEnabled
        "Signatures_Date"     = if($mp.AntivirusSignatureLastUpdated){$mp.AntivirusSignatureLastUpdated}else{"[INDISPONIBLE]"}
        "Signatures_Age_H"    = if($sigAge -gt 0){[Math]::Round($sigAge, 1)}else{"N/A"}
        "Tamper_Protection"   = $mp.IsTamperProtected
        "Exclusions_Actives"  = if($excl){"OUI ($($excl -join ', '))"}else{"NON"}
    } | Format-List

    if ($mp.RealTimeProtectionEnabled -eq $false) {
        if ($avTiers) {
            Write-Host "ℹ INFO : Defender est en mode passif/veille. [$($avTiers -join ' + ')] assure la protection active." -ForegroundColor Cyan
        } else {
            Write-Host "⚠ ALERTE : Aucune protection temps réel ! Le système est à découvert." -ForegroundColor Red
        }
    }
    
    if ($sigAge -gt 24 -and $mp.AntivirusEnabled) { 
        Write-Host "⚠ CONSEIL : Signatures obsolètes (+24h). Vérifiez Windows Update." -ForegroundColor Yellow 
    }

} catch {
    $service = Get-Service WinDefend -ErrorAction SilentlyContinue
    if ($avTiers) {
        Write-Host "ℹ INFO : Defender est verrouillé par le système (0x800106ba)." -ForegroundColor Cyan
        Write-Host ">> CAUSE : [$($avTiers -join ', ')] gère la sécurité. C'est un comportement normal." -ForegroundColor Gray
    } else {
        Write-Host "⚠ ERREUR CRITIQUE : Le moteur Defender est injoignable ($($service.Status))." -ForegroundColor Red
        Write-Host ">> FIX : Vérifiez si un malware ne bloque pas le service WinDefend." -ForegroundColor Gray
    }
}
#----------------------------------------------------
#  3. SMARTSCREEN 
#----------------------------------------------------
Write-Host "`n>>> SmartScreen (Analyse des vecteurs d'entrée) :" -ForegroundColor Yellow
try {
    $smachine = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction SilentlyContinue).SmartScreenEnabled
    $suser    = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction SilentlyContinue).SmartScreenEnabled
    $edge     = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue).EnableSmartScreen

    [PSCustomObject]@{
        "Registry_System (HKLM)" = if($null -ne $smachine){$smachine}else{"[ABSENT/NON-DEFINI]"}
        "Registry_User (HKCU)"   = if($null -ne $suser){$suser}else{"[ABSENT/NON-DEFINI]"}
        "GPO_Policy (Edge)"      = if($null -ne $edge){$edge}else{"[NON-CONFIGURE]"}
    } | Format-List

    if ($smachine -match "Off" -or $null -eq $smachine -or $edge -eq 0) {
        Write-Host "⚠ ETAT : INACTIF (Le système ne bloque pas les fichiers non signés)." -ForegroundColor Red
    if ($Fix -eq "SmartScreen" -or $Fix -eq "All") {
        Invoke-SecurityFix -Type "SmartScreen" 
    } else {
        Write-Host ">> CONSEIL : Relancez avec -Fix pour réparer ce point." -ForegroundColor Gray
    }        
        if ($edge -eq 0) {
            Write-Host ">> FIX GPO DETECTÉE : Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Force" -ForegroundColor Magenta
        }
        
        Write-Host ">> FIX MANUEL (CLI) : New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'RequireAdmin' -PropertyType String -Force" -ForegroundColor Gray
        
        Write-Host ">> FIX MANUEL (GUI) : Sécurité Windows > Contrôle des applis > Protection fondée sur la réputation > Activer tout." -ForegroundColor Gray
    } else {
        Write-Host "OK : SmartScreen est configuré sur [$smachine]." -ForegroundColor Green
    }
} catch {
    Write-Host "SmartScreen non accessible" -ForegroundColor Red
}

#----------------------------------------------------
# 4. DURCISSEMENT IDENTITÉ (LSA - ANTI-MIMIKATZ) 
#----------------------------------------------------
Write-Host "`n>>> Hardening Identité (LSASS Protection) :" -ForegroundColor Yellow

$lsaRaw = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
$lsaVal = $lsaRaw.RunAsPPL

$lsaPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
$lsaForcedOff = $null -ne $lsaPolicy.LsaCfgFlags -and $lsaPolicy.LsaCfgFlags -eq 0

Write-Host "Preuve Registry (RunAsPPL) : " -NoNewline
if ($null -eq $lsaVal) { 
    Write-Host "VALEUR ABSENTE (VULNÉRABLE)" -ForegroundColor Red 
} elseif ($lsaVal -eq 1 -or $lsaVal -eq 2) { 
    Write-Host "$lsaVal" -ForegroundColor Green 
} else { 
    Write-Host "$lsaVal" -ForegroundColor Red 
}

if ($lsaVal -eq 1 -or $lsaVal -eq 2) {
    $mode = if($lsaVal -eq 2){"UEFI (Verrouillé)"} else {"Standard"}
    Write-Host "OK : Le processus LSASS tourne en mode PPL ($mode)." -ForegroundColor Green
} else {
    Write-Host "⚠ VULNÉRABLE : Les outils type Mimikatz peuvent dumper les credentials en mémoire." -ForegroundColor Red
    if ($Fix -eq "LSA" -or $Fix -eq "All") {
        Invoke-SecurityFix -Type "LSA" 
    } else {
        Write-Host ">> CONSEIL : Relancez avec -Fix pour activer la protection LSA." -ForegroundColor Gray
    }    
    if ($lsaForcedOff) {
        Write-Host ">> FIX GPO DETECTÉE : Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags' -Force" -ForegroundColor Magenta
    }

    Write-Host ">> FIX MANUEL (CLI) : Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord" -ForegroundColor Gray
    Write-Host ">> FIX MANUEL (GUI) : Sécurité Windows > Sécurité de l'appareil > Isolation du noyau > Protection de l'autorité de sécurité locale." -ForegroundColor Gray
}

#----------------------------------------------------
# 5. FIREWALL (Dynamique & GPO)
#----------------------------------------------------
Write-Host "`n>>> Pare-feu :" -ForegroundColor Yellow
$fw = Get-NetFirewallProfile
$fw | Select-Object -Property Name, Enabled | Format-Table -AutoSize

if ($fw.Enabled -contains $false) {
    Write-Host "⚠ ALERTE : Un profil Firewall est désactivé !" -ForegroundColor Red
    if ($Fix -eq "Firewall" -or $Fix -eq "All") { 
        Invoke-SecurityFix -Type "Firewall" 
    } else {
        Write-Host ">> CONSEIL : Relancez avec -Fix pour activer la protection Firewall." -ForegroundColor Gray
    }    
    $fwPolicies = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -ErrorAction SilentlyContinue
    if ($null -ne $fwPolicies -and $fwPolicies.EnableFirewall -eq 0) {
        Write-Host ">> FIX GPO DETECTÉE : La stratégie force la coupure. Supprimer les clés dans HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -ForegroundColor Magenta
    }
    Write-Host ">> FIX MANUEL (CLI) : Set-NetFirewallProfile -All -Enabled True" -ForegroundColor Gray
} else {
    Write-Host "OK : Tous les profils Pare-feu sont actifs." -ForegroundColor Green
}

#----------------------------------------------------
# 6. SERVICES CRITIQUES 
#----------------------------------------------------
Write-Host "`n>>> Services sécurité (Système & Tiers) :" -ForegroundColor Yellow
# Liste élargie pour inclure Bitdefender (bdservicehost) car tu l'as sur ton poste
$secServices = "WinDefend","SecurityHealthService","BFE","bdservicehost","mfevtp","McShield","avast","MBAMService","SentinelAgent"
Get-Service $secServices -ErrorAction SilentlyContinue |
Select-Object -Property Name, Status, StartType | Format-Table -AutoSize

#----------------------------------------------------
# 7. ANALYSE VULNÉRABILITÉ RÉSEAU (SMBv1 & LLMNR) 
#----------------------------------------------------

Write-Host "`n>>> Analyse vulnérabilité réseau (Surface d'attaque) :" -ForegroundColor Yellow

# 1. SMBv1
$smb1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
if ($smb1 -eq $true) {
    Write-Host "⚠ DANGER : SMBv1 est activé (Vecteur Ransomware/WannaCry)." -ForegroundColor Red
    if ($Fix -eq "SMBv1" -or $Fix -eq "All") {
        Invoke-SecurityFix -Type "SMBv1"
    } else {
        Write-Host ">> CONSEIL : Relancez avec -Fix pour réparer ce point." -ForegroundColor Gray
    }
    Write-Host ">> FIX MANUEL (CLI) : Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" -ForegroundColor Gray
} else {
    Write-Host "OK : SMBv1 est désactivé." -ForegroundColor Green
}

# 2. LLMNR (Anticipation dynamique via GPO)
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$llmnrVal = (Get-ItemProperty $llmnrPath -ErrorAction SilentlyContinue).EnableMulticast

# Si la valeur n'est pas 0, LLMNR est potentiellement actif (par défaut Windows l'active)
if ($null -eq $llmnrVal -or $llmnrVal -ne 0) {
    Write-Host "⚠ ATTENTION : LLMNR est actif (Risque d'empoisonnement NTLM/Responder)." -ForegroundColor Yellow
    Write-Host ">> FIX MANUEL (GPO) : New-ItemProperty -Path '$llmnrPath' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force" -ForegroundColor Gray
} else {
    Write-Host "OK : LLMNR est désactivé via stratégie." -ForegroundColor Green
}

#----------------------------------------------------
# 8. SYNTHÈSE MULTI-AV (Logique Intelligente)
#----------------------------------------------------

Write-Host "`n>>> Check multi-antivirus & Conflits :" -ForegroundColor Yellow

$activeAV = $avProducts | Where-Object { $_.state -eq "ACTIF" }

if ($avProducts.Count -gt 1) {
    Write-Host "ℹ INFO : $($avProducts.Count) solutions installées : [$($avProducts.displayName -join ' / ')]." -ForegroundColor Cyan
    
    if ($activeAV.Count -gt 1) {
        Write-Host "⚠ DANGER : $($activeAV.Count) antivirus sont ACTIFS simultanément !" -ForegroundColor Red
        Write-Host "RISQUE : Conflits critiques de pilotes (BSOD), ralentissements et exclusions mutuelles." -ForegroundColor Red
        Write-Host ">> ACTION : Désinstallez l'une des solutions ou vérifiez le mode passif." -ForegroundColor Gray
    } else {
        Write-Host "OK : Cohabitation propre détectée. Seul [$($activeAV.displayName)] assure la protection temps réel." -ForegroundColor Green
    }
} elseif ($avProducts.Count -eq 1) {
    Write-Host "OK : Protection mono-source détectée ($($avProducts.displayName))." -ForegroundColor Green
} else {
    Write-Host "⚠ CRITIQUE : Aucun antivirus enregistré dans le Security Center." -ForegroundColor Red
    Write-Host ">> FIX : Vérifiez l'état du service WinDefend ou réinstallez votre solution de sécurité." -ForegroundColor Gray
}

Write-Host "`n================ FIN DIAG : $(Get-Date -Format 'dd/MM/yyyy HH:mm') =================" -ForegroundColor Cyan


#----------------------------------------------------
# STOP TRANSCRIPTION 
#----------------------------------------------------

if ($ShareDpaste -or $ShareGofile) {
    try { Stop-Transcript | Out-Null } catch { }   # ← remplace le if ($PSRawHost...)

    $PathBureau = "$env:USERPROFILE\Desktop\Rapport_EDR.txt"

    if (Test-Path $PathBureau) {
        $cleanContent = Get-Content $PathBureau |
            Select-Object -Skip 20 |
            Select-Object -SkipLast 4
        $cleanContent | Out-File $PathBureau -Force -Encoding UTF8
    }
}

#----------------------------------------------------
# PARTAGE DE RAPPORT (DPASTE ET/OU GOFILE)
#----------------------------------------------------

$file = "$env:USERPROFILE\Desktop\Rapport_EDR.txt"

if ($ShareDpaste -or $ShareGofile) {
    
    try { Stop-Transcript | Out-Null } catch { }

    if (-not (Test-Path $file)) {
        "Rapport de sécurité EDR - $(Get-Date)" | Out-File $file -Encoding UTF8
    }

    Write-Host "`n=== PHASE D'UPLOAD ===" -ForegroundColor Cyan

    #  DPASTE 
    if ($ShareDpaste) {
        Write-Host "[cloud] Envoi vers dpaste..." -ForegroundColor Magenta -NoNewline
        try {
            if (-not (Test-Path $file)) {
                throw "Fichier rapport introuvable : $file"
            }

            $rapportContenu = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

            if ([string]::IsNullOrWhiteSpace($rapportContenu)) {
                throw "Le fichier rapport est vide."
            }

            Write-Host " [$($rapportContenu.Length) chars]" -NoNewline -ForegroundColor DarkGray

            $encodedContent = [System.Uri]::EscapeDataString($rapportContenu)
            $bodyString = "content=$encodedContent&expiry_days=7&syntax=text"

            $response = Invoke-RestMethod -Uri "https://dpaste.com/api/v2/" `
                                          -Method Post `
                                          -Body $bodyString `
                                          -ContentType "application/x-www-form-urlencoded"

            $urlD = $response.Trim()

            if ($urlD -match "https://dpaste\.com/") {
                Write-Host " -> OK" -ForegroundColor Green
                Write-Host " LIEN DPASTE : " -NoNewline
                Write-Host $urlD -ForegroundColor Yellow
                "$(Get-Date) : DPASTE -> $urlD" | Out-File "$env:USERPROFILE\Desktop\liens_upload.txt" -Append
            } else {
                Write-Host " -> ERREUR (réponse inattendue)" -ForegroundColor Red
                Write-Host " Détail : $urlD" -ForegroundColor Gray
            }

        } catch {
            Write-Host " -> ERREUR CRITIQUE : $_" -ForegroundColor Red
        }
    }

    # --- GOFILE ---
    if ($ShareGofile) {
        Write-Host "[cloud] Envoi vers Gofile..." -ForegroundColor Cyan -NoNewline
        try {
            # ✅ Récupère le bon serveur dynamiquement (store1 peut changer)
            $serverResp = Invoke-RestMethod -Uri "https://api.gofile.io/servers" -Method Get
            $server = $serverResp.data.servers[0].name

            $resp = curl.exe -s -F "file=@$file" "https://$server.gofile.io/uploadFile"
            $uploadJson = $resp | ConvertFrom-Json

            if ($uploadJson.status -eq "ok") {
                $dl = $uploadJson.data.downloadPage
                Write-Host " -> OK" -ForegroundColor Green
                Write-Host " LIEN GOFILE : " -NoNewline
                Write-Host $dl -ForegroundColor Yellow
                "$(Get-Date) : GOFILE  -> $dl" | Out-File "$env:USERPROFILE\Desktop\liens_upload.txt" -Append
            } else {
                Write-Host " -> ERREUR : $($uploadJson.status)" -ForegroundColor Red
            }
        } catch {
            Write-Host " -> ERREUR CRITIQUE : $_" -ForegroundColor Red
        }
    }

    $esc = [char]27
    $dir = $env:USERPROFILE + "\Desktop"
    $urlLocal = "file:///" + ($dir.Replace('\','/'))
    $linkLocal = "$esc]8;;$urlLocal$esc\$dir$esc]8;;$esc\"
    Write-Host "`n DOSSIER SOURCE : " -NoNewline
    Write-Host $linkLocal -ForegroundColor Yellow
}
}
