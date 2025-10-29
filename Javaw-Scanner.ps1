function Analyze-MinecraftJavaw-V7 {
    param(
        [string]$ProcessName = "javaw",
        [string[]]$SuspiciousFragments = @(
            "javaagent", "Xbootclasspath", "wurst", "aristois", "meteor", "impact",
            "sigma", "kryptonite", "liquidbounce", "viaversion", "viabackwards",
            "modlauncher", "spongepowered", "forge"
        ),
        [int]$MaxSuspiciousArgs = 0
    )

    function Draw-Separator {
        Write-Host "==================================================" -ForegroundColor DarkGray
    }

    Write-Host "@@@@@@    @@@@@@      @@@       @@@@@@@@   @@@@@@   @@@@@@@   @@@  @@@     @@@  @@@@@@@  " -ForegroundColor Cyan
    Write-Host "@@@@@@@   @@@@@@@      @@@       @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@ @@@     @@@  @@@@@@@  " -ForegroundColor Cyan
    Write-Host "!@@       !@@          @@!       @@!       @@!  @@@  @@!  @@@  @@!@!@@@     @@!    @@!    " -ForegroundColor Cyan
    Write-Host "!@!       !@!          !@!       !@!       !@!  @!@  !@!  @!@  !@!!@!@!     !@!    !@!    " -ForegroundColor Cyan
    Write-Host "!!@@!!    !!@@!!       @!!       @!!!:!    @!@!@!@!  @!@!!@!   @!@ !!@!     !!@    @!!    " -ForegroundColor Cyan
    Write-Host " !!@!!!    !!@!!!      !!!       !!!!!:    !!!@!!!!  !!@!@!    !@!  !!!     !!!    !!!    " -ForegroundColor Cyan
    Write-Host "     !:!       !:!     !!:       !!:       !!:  !!!  !!: :!!   !!:  !!!     !!:    !!:    " -ForegroundColor Cyan
    Write-Host "    !:!       !:!       :!:      :!:       :!:  !:!  :!:  !:!  :!:  !:!     :!:    :!:    " -ForegroundColor Cyan
    Write-Host ":::: ::   :::: ::       :: ::::   :: ::::  ::   :::  ::   :::   ::   ::      ::     ::  " -ForegroundColor Cyan
    Write-Host ":: : :    :: : :       : :: : :  : :: ::    :   : :   :   : :  ::    :      :       :" -ForegroundColor Cyan
    Write-Host "[JAVAW SCANNER BY SS LEARN IT]" -ForegroundColor Cyan
    Draw-Separator
    Write-Host ""

    $overallSuspiciousCount = 0
    $suspiciousResults = @()
    $suspiciousIndex = 1

    Write-Host "🔬 FASE 1: Analisi in Tempo Reale (Frammenti sospetti negli argomenti di processo)" -ForegroundColor White

    $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue

    if ($processes) {
        foreach ($proc in $processes) {
            $commandLine = ""
            try {
                $commandLine = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" | Select-Object -ExpandProperty CommandLine
            }
            catch {
                $commandLine = "⛔ ERRORE: Accesso negato (Eseguire come Amministratore)"
                $overallSuspiciousCount += 10
            }

            $suspiciousArgsFound = @()
            foreach ($fragment in $SuspiciousFragments) {
                if ($commandLine -match $fragment) {
                    $suspiciousArgsFound += $fragment
                }
            }

            if ($suspiciousArgsFound.Count -gt 0) {
                $overallSuspiciousCount += $suspiciousArgsFound.Count
                $suspiciousResults += [PSCustomObject]@{
                    Index = $suspiciousIndex++
                    Tipo = "Esecuzione Attiva (PID $($proc.Id))"
                    Risultato = "Rilevata presenza di frammenti sospetti: $($suspiciousArgsFound -join ' | ')"
                }
            }
        }

        if ($suspiciousResults.Count -eq 0) {
            Write-Host "  > Nessun frammento sospetto rilevato negli argomenti di processo." -ForegroundColor Green
        }
    } else {
        Write-Host "  > Nessun processo '$ProcessName' in esecuzione." -ForegroundColor DarkGray
    }

    Write-Host ""
    Draw-Separator

    if ($overallSuspiciousCount -gt $MaxSuspiciousArgs) {
        $finalColor = if ($overallSuspiciousCount -ge 5) { "Red" } else { "DarkYellow" }
        $finalLabel = if ($overallSuspiciousCount -ge 5) { "ALLARME ROSSO - RISCHIO CRITICO" } else { "ALLARME GIALLO - RISCHIO MODERATO" }

        Write-Host "🚨 RISULTATO FINALE: [ $finalLabel ] - $($overallSuspiciousCount) Frammenti sospetti totali!" -ForegroundColor $finalColor
        Draw-Separator

        Write-Host "Dettaglio degli Index Sospetti Rilevati:" -ForegroundColor $finalColor
        foreach ($res in $suspiciousResults) {
            Write-Host "  [INDEX $($res.Index)] | TIPO: $($res.Tipo) | RISULTATO: $($res.Risultato)" -ForegroundColor $finalColor
        }

        Write-Host ""
        Write-Host "👉 AZIONE CONSIGLIATA:" -ForegroundColor $finalColor
        if ($overallSuspiciousCount -ge 5) {
            Write-Host "- BAN IMMEDIATO dell'utente (Presenza di frammenti altamente sospetti)." -ForegroundColor Red
        } else {
            Write-Host "- INDAGINE MANUALE e monitoraggio (Frammenti isolati o non conclusivi)." -ForegroundColor DarkYellow
        }
    }
    else {
        Write-Host "✅ RISULTATO FINALE: [SAFE] Nessun frammento sospetto rilevato." -ForegroundColor Green
        Draw-Separator
    }
}

Analyze-MinecraftJavaw-V7
