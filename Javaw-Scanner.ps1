function Analyze-MinecraftJavaw-V25 {
    param(
        # Variabili non usate mantenute per coerenza
        [string[]]$SuspiciousFiles = @(), 
        [string[]]$ScanPaths = @(),
        [int]$MaxSuspiciousArgs = 0
    )

    function Draw-Separator {
        Write-Host "==================================================" -ForegroundColor DarkGray
    }

    # Banner aggiornato
    Write-Host "@@@@@@    @@@@@@      @@@         @@@@@@@@    @@@@@@  @@@@@@@    @@@ @@@       @@@  @@@@@@@  " -ForegroundColor Cyan
    Write-Host "@@@@@@@   @@@@@@@     @@@         @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@ @@@       @@@  @@@@@@@  " -ForegroundColor Cyan
    Write-Host "!@@       !@@          @@!        @@!       @@! @@@   @@! @@@   @@!@!@@@        @@!    @@!    " -ForegroundColor Cyan
    Write-Host "!@!       !@!          !@!        !@!       !@! @!@   !@! @!@   !@!!@!@!        !@!    !@!    " -ForegroundColor Cyan
    Write-Host "!!@@!!    !!@@!!        @!!       @!!!:!    @!@!@!@!  @!@!!@!    @!@ !!@!        !!@    @!!    " -ForegroundColor Cyan
    Write-Host " !!@!!!    !!@!!!       !!!       !!!!!:    !!!@!!!!  !!@!@!     !@!  !!!        !!!    !!!    " -ForegroundColor Cyan
    Write-Host "    !:!       !:!       !!:       !!:       !!: !!!   !!: :!!    !!:  !!!        !!:    !!:    " -ForegroundColor Cyan
    Write-Host "    !:!       !:!        :!:      :!:       :!: !:!   :!:  !:!   :!:  !:!        :!:    :!:    " -ForegroundColor Cyan
    Write-Host ":::: ::   :::: ::        :: ::::  :: ::::   ::  :::   ::  :::     ::   ::         ::      ::  " -ForegroundColor Cyan
    Write-Host ":: : :    :: : :         : :: : : : :: ::     : :      : :      ::    :          :        : " -ForegroundColor Cyan
    Write-Host "[JAVAW SCANNER]" -ForegroundColor Red 
    Draw-Separator
    Write-Host ""

    $overallSuspiciousCount = 0
    $suspiciousResults = @()
    $suspiciousIndex = 1
    
    # --- FASE DI SCANSIONE LOG (AZIONE UNICA E PRIORITARIA) ---
    Write-Host "📜 FASE DI SCANSIONE LOG: Ricerca e Analisi dei File di Log (Verifica diretta mod/cheat)." -ForegroundColor White
    
    $logSearchPaths = @(
        "$env:APPDATA\.minecraft\logs\latest.log",
        "$env:APPDATA\.minecraft\logs\debug.log",
        "$env:APPDATA\.minecraft\logs\*.log", # Generico
        "$env:APPDATA\MultiMC\instances\*\minecraft\logs\latest.log", # Esempio di Launcher alternativo
        "$env:APPDATA\MultiMC\instances\*\.minecraft\logs\latest.log" # Variazione
    )
    $logSuspiciousFragments = @(
        "javaagent", "injection", "hook", "wurst", "aristois", "meteor", "impact", "sigma", "liquidbounce",
        "Loading library", "modlauncher.LaunchServiceRunner", "Starting minecraft client", 
        "Starting net.minecraft.client.main.Main"
    )

    $logFilesToAnalyze = @()

    # Raccogli i percorsi di log esistenti
    foreach ($path in $logSearchPaths) {
        $logFilesToAnalyze += Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    }
    
    $logFilesToAnalyze = $logFilesToAnalyze | Select-Object -Unique

    if ($logFilesToAnalyze.Count -eq 0) {
        Write-Host "  > Nessun file di log standard di Minecraft/Launcher trovato. Necessario cercare manualmente in cartelle personalizzate." -ForegroundColor DarkYellow
    }
    else {
        foreach ($logFile in $logFilesToAnalyze) {
            
            $logFileName = [System.IO.Path]::GetFileName($logFile)
            Write-Host "  > Analizzo il file: $($logFileName)" -ForegroundColor DarkGray
            
            # Legge il contenuto del log (gestendo la potenziale dimensione)
            $logContent = Get-Content -Path $logFile -ErrorAction SilentlyContinue

            if ($logContent) {
                $logHits = @()
                $isSuspiciousLog = $false
                

                # --- Ricerca Modifiche JVM/Cheat ---
                foreach ($fragment in $logSuspiciousFragments) {
                    # Ricerca case-insensitive
                    if ($logContent -match [regex]::Escape($fragment)) {
                        $logHits += $fragment
                        # Identifica come sospetto grave
                        if ($fragment -in @("javaagent", "injection", "hook", "wurst", "aristois", "meteor", "impact", "sigma", "liquidbounce", "doomsday")) {
                            $isSuspiciousLog = $true
                        }
                    }
                }
                
                $uniqueLogHits = $logHits | Select-Object -Unique
                
                if ($isSuspiciousLog) {
                    $overallSuspiciousCount += 15
                    # Cerca la prima linea che contiene una prova grave per il dettaglio
                    # La ricerca è sempre case-sensitive qui per mantenere la precisione del dettaglio
                    $firstHitLine = $logContent | Select-String -Pattern "javaagent|wurst|hook|aristois|meteor|sigma" -CaseSensitive | Select-Object -First 1
                    
                    $suspiciousResults += [PSCustomObject]@{
                        Index = $suspiciousIndex++
                        Tipo = "TRACCIA DIRETTA LOG ($logFileName)"
                        Risultato = "Rilevato ARGOMENTO/CHEAT Sospetto: $($uniqueLogHits -join ' | ')"
                        Dettaglio = "Linea: $($firstHitLine.LineNumber) | Contenuto: $($firstHitLine.Line.Substring(0, [System.Math]::Min(100, $firstHitLine.Line.Length)))..."
                    }
                    Write-Host "   > [TRACCIA LOG] ALLARME ROSSO nel log: $($logFileName)" -ForegroundColor Red
                }
                elseif ($uniqueLogHits.Count -gt 0) {
                    Write-Host "   > [ANALISI LOG] Trovate tracce di avvio/mod: $($uniqueLogHits -join ' | ') in $($logFileName)" -ForegroundColor Yellow
                }
            }
        }
    }
    
    Draw-Separator
    
    # --- RISULTATO FINALE E ISTRUZIONI ---
    
    if ($overallSuspiciousCount -gt $MaxSuspiciousArgs) {
        $finalColor = if ($overallSuspiciousCount -ge 15) { "Red" } 
                      else { "DarkYellow" }
        $finalLabel = if ($overallSuspiciousCount -ge 15) { "ALLARME ROSSO - PROVA TROVATA" } 
                      else { "ALLARME GIALLO - RISCHIO MODERATO" }

        Write-Host "🚨 RISULTATO FINALE: [ $finalLabel ] - $($overallSuspiciousCount) Frammenti sospetti totali nei Log!" -ForegroundColor $finalColor
        Draw-Separator

        # Dettaglio dei Frammenti Sospetti
        if ($suspiciousResults.Count -gt 0) {
            Write-Host "🔥 DETTAGLIO PROVE RILEVATE (Log):" -ForegroundColor Red
            foreach ($res in $suspiciousResults) {
                Write-Host "  [INDEX $($res.Index)] | TIPO: $($res.Tipo)" -ForegroundColor Red
                Write-Host "  RISULTATO: $($res.Risultato)" -ForegroundColor Red
                Write-Host "  DETTAGLIO: $($res.Dettaglio)" -ForegroundColor DarkGray
            }
            Draw-Separator
        }

        Write-Host ""
        Write-Host "👉 AZIONE CONSIGLIATA:" -ForegroundColor $finalColor
        
        if ($overallSuspiciousCount -ge 15) {
            Write-Host "- BAN IMMEDIATO (Prova diretta trovata nei Log)." -ForegroundColor Red
        } else {
            Write-Host "- NESSUNA TRACCIA SOSPETTA RILEVATA." -ForegroundColor Green
        }
    }
    else {
        Write-Host "✅ RISULTATO FINALE: [SAFE] Nessuna traccia diretta di cheat rilevata nei Log." -ForegroundColor Green
        
        Write-Host ""
        Write-Host "NOTA BENE: Eseguita SOLO la scansione dei LOG. Se negativo, è probabile che l'utente abbia cancellato o offuscato i log." -ForegroundColor DarkYellow
        
        Draw-Separator
    }
}

# Esecuzione predefinita: SOLO SCANSIONE LOG
Analyze-MinecraftJavaw-V25
