# EDRauditAV

> Audit et remédiation de la sécurité Windows — Firewall, Defender, SmartScreen, LSA, SMBv1  
> Auteur : [ps81frt](https://github.com/ps81frt/EDRauditAV)

---

## Description

Script PowerShell d'audit complet de la posture de sécurité Windows. Il inspecte les composants critiques, détecte les configurations vulnérables et peut appliquer des corrections ciblées. Il supporte l'export et le partage du rapport en ligne.

---

## Prérequis

- Windows 10 / 11
- PowerShell 5.1 ou supérieur
- **Droits Administrateur requis** pour les opérations `-Fix`

---

## Utilisation

```powershell
# Audit lecture seule
.\EDRauditAV.ps1

# Afficher l'aide
.\EDRauditAV.ps1 -Help

# Réparer un composant spécifique
.\EDRauditAV.ps1 -Fix Firewall
.\EDRauditAV.ps1 -Fix SmartScreen
.\EDRauditAV.ps1 -Fix Defender
.\EDRauditAV.ps1 -Fix SMBv1
.\EDRauditAV.ps1 -Fix LSA

# Tout réparer
.\EDRauditAV.ps1 -Fix All
```
## Utilisation rapide + upload partage

```powershell
&{
    $EDRauditAV = {
        Clear-Host
        $repoZip = "$env:TEMP\EDRauditAV.zip"
        $extract = "$env:TEMP\EDRauditAV"

        Invoke-WebRequest "https://github.com/ps81frt/EDRauditAV/archive/refs/heads/main.zip" -OutFile $repoZip
        Unblock-File $repoZip -ErrorAction SilentlyContinue
        Expand-Archive $repoZip $extract -Force

        $dir = Get-ChildItem "$extract" -Recurse -Filter "EDRauditAV.ps1" |
            Select-Object -First 1

        if (-not $dir) {
            throw "EDRauditAV.ps1 introuvable."
        }

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

        & $dir.FullName -ShareDpaste -ShareGofile

        function Write-ClickableLink {
            param([string]$Label, [string]$Path)
            $esc = [char]27
            Write-Host "${esc}]8;;file://$Path${esc}\$Label${esc}]8;;${esc}\" -ForegroundColor Yellow
        }

        $outDir = "$env:USERPROFILE\Desktop\EDR_$(Get-Date -Format 'yyyyMMdd')"

        Write-Host "`n=== Fichiers ===" -ForegroundColor Cyan
        Write-Host "Dossier rapport :"
        Write-ClickableLink -Label $outDir -Path $outDir
        Write-Host "Emplacement script :"
        Write-ClickableLink -Label $($dir.Directory.FullName) -Path $dir.Directory.FullName
    }
    & $EDRauditAV
}
```
---

## Paramètres

| Paramètre | Type | Description |
|---|---|---|
| `-Fix` | String | Cible de remédiation : `Firewall`, `SmartScreen`, `Defender`, `SMBv1`, `LSA`, `All`, `None` (défaut) |
| `-ShareDpaste` | Switch | Lance l'audit, génère le rapport et l'upload sur [dpaste.com](https://dpaste.com) (lien web, lecture directe) |
| `-ShareGofile` | Switch | Lance l'audit, génère le rapport et l'upload sur [gofile.io](https://gofile.io) (téléchargement fichier) |
| `-Help` | Switch | Affiche l'aide intégrée |

---

## Modules d'audit

| # | Section | Ce qui est vérifié |
|---|---|---|
| 1 | Antivirus (Security Center) | Produits enregistrés, état, `productState` brut |
| 2 | Windows Defender | Moteur, protection temps réel, age signatures, exclusions, mode passif |
| 3 | SmartScreen | Activation, valeur registre, blocage GPO |
| 4 | Protection LSA | `RunAsPPL`, verrouillage mémoire LSASS |
| 5 | Pare-feu Windows | Profils Domain / Private / Public, blocage GPO |
| 6 | Services critiques | WinDefend, BFE, SecurityHealthService, agents tiers |
| 7 | Vulnérabilités réseau | SMBv1 (CVE-2017-0144 / WannaCry), LLMNR (Responder) |
| 8 | Synthèse multi-AV | Détection de conflits, mode passif, couverture |

---

## Export & Partage

```powershell
# Export manuel vers le Bureau
.\EDRauditAV.ps1 *> "$env:USERPROFILE\Desktop\Rapport_EDR.txt"

# Upload automatique vers dpaste (lien web partageable)
.\EDRauditAV.ps1 -ShareDpaste

# Upload automatique vers Gofile (fichier téléchargeable)
.\EDRauditAV.ps1 -ShareGofile

# Les deux simultanément
.\EDRauditAV.ps1 -ShareDpaste -ShareGofile
```

Les liens générés sont sauvegardés dans :
```
%USERPROFILE%\Desktop\liens_upload.txt
```

---

## Exemples de sortie

```
================ DIAG SECURITE COMPLET =================

>>> Antivirus détectés (WMI / Security Center) :
Nom                   Etat   EtatBrut
----                  ----   --------
Windows Defender      ACTIF  397568

>>> Windows Defender (détail complet) :
OK : Protection temps réel active.
OK : Signatures à jour (< 24h).

>>> Pare-feu Windows :
OK : Tous les profils Pare-feu sont actifs.

>>> Analyse vulnérabilité réseau :
OK : SMBv1 est désactivé.
⚠ ATTENTION : LLMNR est actif (Risque d'empoisonnement NTLM/Responder).

================ FIN DIAG : 16/04/2026 02:20 =================

=== PHASE D'UPLOAD ===
[cloud] Envoi vers dpaste... [3955 chars] -> OK
 LIEN DPASTE : https://dpaste.com/XXXXXXXX
```

---

## Remédiation automatique

> ⚠ Nécessite PowerShell en mode **Administrateur**

| Cible | Action |
|---|---|
| `Firewall` | Supprime les GPO bloquantes, reset `netsh advfirewall` |
| `SmartScreen` | Supprime le blocage GPO, force `RequireAdmin` |
| `Defender` | Réactive `RealTimeProtection`, `PUAProtection`, `BlockAtFirstSeen` |
| `SMBv1` | Désactive `EnableSMB1Protocol` (CVE-2017-0144) |
| `LSA` | Active `RunAsPPL` (`HKLM\SYSTEM\...\Lsa`) |

---

## Licence

MIT — libre d'utilisation, de modification et de distribution.
