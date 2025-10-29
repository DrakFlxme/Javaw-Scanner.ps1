function Analyze-MinecraftJavaw-V7 {
    param(
        [string]$ProcessName = "javaw",
        # ----------------------------------------------------
        # 1. ARGOMENTI DI ESECUZIONE (Rilevamento in tempo reale)
        # ----------------------------------------------------
        [string[]]$ExplicitCheatArgs = @(
            "-javaagent:",              # L'indicatore di iniezione più forte e universale
            "-Xbootclasspath/a:",       # Alterazione del classpath di avvio, alto rischio
            "client.wurst",             # Wurst client
            "aristois",                 # Aristois client
            "meteor-client",            # Meteor client
            "impact.client",            # Impact client
            "sigma5",                   # Sigma client
            "kryptonite",               # Client meno comuni ma noti
            "liquidbounce",             # LiquidBounce client
            "viaversion",               # Potenzialmente sospetto in ambienti non autorizzati
            "viabackwards",             # Potenzialmente sospetto in ambienti non autorizzati
            "cpw.mods.modlauncher",     # Alcuni cheat usano launcher moddati
            "org.spongepowered.asm",    # Potrebbe indicare alterazioni del bytecode (Mixins)
            "net.minecraftforge.fml"    # Alcuni cheat si mascherano da mod Forge
        ),
        # ----------------------------------------------------
        # 2. TRACCE SUL DISCO (Rilevamento storico/forense)
        # ----------------------------------------------------
        # Cartelle e file specifici lasciati dai client cheat noti o da injector comuni
        [string[]]$ExplicitCheatPaths = @(
            # Wurst / KAMI
            "$env:APPDATA\.minecraft\mods\wurst",
            "$env:APPDATA\.minecraft\versions\wurst",
            "$env:APPDATA\.minecraft\mods\kami",
            # Aristois / LiquidBounce / Impact
            "$env:APPDATA\.minecraft\libraries\aristois",
            "$env:APPDATA\.minecraft\versions\aristois",
            "$env:APPDATA\.minecraft\versions\liquidbounce",
            "$env:APPDATA\.minecraft\versions\impact",
            # Meteor / Salhack
            "$env:APPDATA\.minecraft\meteor-client",
            "$env:APPDATA\.minecraft\salhack",
            # Client Injector e Tracce Comuni
            "$env:LOCALAPPDATA\temp\temp_cheat.jar", # File temporaneo sospetto
            "$env:APPDATA\.config\cheats",
            "$env:APPDATA\.minecraft\mods\fabric-api-hack.jar" # Mascheramento
        ),
        [int]$MaxSuspiciousArgs = 0 # Qualsiasi hit esplicito è allarme
    )

    function Draw-Separator {
        Write-Host "==================================================" -ForegroundColor DarkGray
    }

    # ----------------------------------------------------
    # LOGO BANNER DI AVVIO (SS Learn staccato, colore ROSSO)
    # ----------------------------------------------------
    Write-Host -ForegroundColor Red " ██████╗  ██████╗    ██╗     ███████╗ █████╗ ██████╗ ███╗   ██╗"
    Write-Host -ForegroundColor Red "██╔═══██╗██╔═══██╗   ██║     ██╔════╝██╔══██╗██╔══██╗████╗  ██║"
    Write-Host -ForegroundColor Red "███████║███████║    ██║     █████╗  ███████║██████╔╝██╔████╔██║"
    Write-Host -ForegroundColor Red "╚═══██╔╝ ╚═══██╔╝   ██║     ██╔══╝  ██╔══██║██╔══██╗██║╚██╔╝██║"
    Write-Host -ForegroundColor Red "██████╔╝ ██████╔╝   ███████╗███████╗██║  ██║██║  ██║██║  ╚═╝ ██║"
    Write-Host -ForegroundColor Red "╚═════╝  ╚═════╝    ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝"
    Write-Host -ForegroundColor Red "[JAVAW SCANNER BY SS LEARN IT]"
    Draw-Separator
    Write-Host ""
    # ----------------------------------------------------

    $overallSuspiciousCount = 0
    $suspiciousResults = @()
    $suspiciousIndex = 1

    
    # ----------------------------------------------------
    # FASE 1: Analisi in Tempo Reale (javaw.exe)
    # ----------------------------------------------------
    Write-Host "🔬 FASE 1: Analisi in Tempo Reale (Argomenti Processo attivo)" -ForegroundColor White

    $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue

    if ($processes) {
        foreach ($proc in $processes) {
            $commandLine = ""
            try {
                # !!! ESEGUIRE COME AMMINISTRATORE !!!
                $commandLine = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" | Select-Object -ExpandProperty CommandLine
            }
            catch {
                $commandLine = "⛔ ERRORE: Accesso negato (Eseguire come Amministratore)"
                $overallSuspiciousCount += 10 # Peso molto alto per fallimento accesso
            }

            $suspiciousArgsFound = @()
            foreach ($arg in $ExplicitCheatArgs) {
                if ($commandLine -match [regex]::Escape($arg)) {
                    $suspiciousArgsFound += $arg
                }
            }

            if ($suspiciousArgsFound.Count -gt 0) {
                $overallSuspiciousCount += $suspiciousArgsFound.Count
                $suspiciousResults += [PSCustomObject]@{
                    Index = $suspiciousIndex++
                    Tipo = "Esecuzione Attiva (PID $($proc.Id))"
                    Risultato = "Rilevata traccia di iniezione: $($suspiciousArgsFound -join ' | ')"
                }
            }
        }
        if ($suspiciousResults -notmatch 'Esecuzione Attiva') { Write-Host "  > Nessun argomento di lancio esplicito rilevato." -ForegroundColor Green }
    } else {
        Write-Host "  > Nessun processo '$ProcessName' in esecuzione." -ForegroundColor DarkGray
    }


    # ----------------------------------------------------
    # FASE 2: Analisi Forense (Tracce su Disco)
    # ----------------------------------------------------

    Write-Host ""
    Write-Host "📂 FASE 2: Analisi Forense (Tracce su Disco)" -ForegroundColor White
    $diskTracesFound = $false
    
    foreach ($path in $ExplicitCheatPaths) {
        $expandedPath = $ExecutionContext.InvokeCommand.ExpandString($path) 
        
        if (Test-Path -Path $expandedPath) {
            $diskTracesFound = $true
            $overallSuspiciousCount += 5 # Peso molto alto, l'installazione è certa
            $baseName = Split-Path $expandedPath -Leaf
            $suspiciousResults += [PSCustomObject]@{
                Index = $suspiciousIndex++
                Tipo = "Installazione Locale / Traccia"
                Risultato = "Trovata traccia esplicita di cheat: **$baseName** in '$expandedPath'"
            }
        }
    }

    if (-not $diskTracesFound) {
        Write-Host "  > Nessuna traccia di installazione di client noti rilevata." -ForegroundColor Green
    }
    
    
    # ----------------------------------------------------
    # 3. DETERMINAZIONE RISULTATO FINALE E GRAFICA
    # ----------------------------------------------------

    Write-Host ""
    Draw-Separator

    if ($overallSuspiciousCount -gt $MaxSuspiciousArgs) {
        # Livello Rosso/Giallo: Allarme
        $finalColor = if ($overallSuspiciousCount -ge 5) { "Red" } else { "DarkYellow" }
        $finalLabel = if ($overallSuspiciousCount -ge 5) { "ALLARME ROSSO - RISCHIO CRITICO" } else { "ALLARME GIALLO - RISCHIO MODERATO" }
        
        Write-Host "🚨 RISULTATO FINALE: [ $finalLabel ] - $($overallSuspiciousCount) Indizi Sospetti Totali!" -ForegroundColor $finalColor
        Draw-Separator
        
        Write-Host "Dettaglio degli Index Sospetti Rilevati:" -ForegroundColor $finalColor
        foreach ($res in $suspiciousResults) {
            Write-Host "  [INDEX $($res.Index)] | TIPO: $($res.Tipo) | RISULTATO: $($res.Risultato)" -ForegroundColor $finalColor
        }
        
        Write-Host ""
        Write-Host "👉 AZIONE CONSIGLIATA:" -ForegroundColor $finalColor
        if ($overallSuspiciousCount -ge 5) {
             Write-Host "- BAN IMMEDIATO dell'utente (Installazione/Iniezione di cheat esplicita)." -ForegroundColor Red
        } else {
             Write-Host "- INDAGINE MANUALE e monitoraggio (Trovato un indizio debole o isolato)." -ForegroundColor DarkYellow
        }
    }
    else {
        # Livello Verde: Pulito
        Write-Host "✅ RISULTATO FINALE: [SAFE] Nessun indizio esplicito di cheat client noto rilevato." -ForegroundColor Green
        Draw-Separator
    }
}

# Esegui la funzione
Analyze-MinecraftJavaw-V7

