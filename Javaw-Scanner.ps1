function Analyze-MinecraftJavaw-V7 {
    param(
        [string]$ProcessName = "javaw",
        [string[]]$ExplicitCheatArgs = @(
            "-javaagent:",
            "-Xbootclasspath/a:",
            "client.wurst",
            "aristois",
            "meteor-client",
            "impact.client",
            "sigma5",
            "kryptonite",
            "liquidbounce",
            "viaversion",
            "viabackwards",
            "cpw.mods.modlauncher",
            "org.spongepowered.asm",
            "net.minecraftforge.fml"
        ),
        [string[]]$ExplicitCheatPaths = @(
            "$env:APPDATA\.minecraft\mods\wurst",
            "$env:APPDATA\.minecraft\versions\wurst",
            "$env:APPDATA\.minecraft\mods\kami",
            "$env:APPDATA\.minecraft\libraries\aristois",
            "$env:APPDATA\.minecraft\versions\aristois",
            "$env:APPDATA\.minecraft\versions\liquidbounce",
            "$env:APPDATA\.minecraft\versions\impact",
            "$env:APPDATA\.minecraft\versions\doomsday",
            "$env:APPDATA\.minecraft\meteor-client",
            "$env:APPDATA\.minecraft\salhack",
            "$env:LOCALAPPDATA\temp\temp_cheat.jar",
            "$env:APPDATA\.config\cheats",
            "$env:APPDATA\.minecraft\mods\fabric-api-hack.jar"
        ),
        [string[]]$SuspiciousFilePatterns = @(
            "wurst", "aristois", "meteor", "impact", "sigma", "liquidbounce",
            "kami", "salhack", "krypton", "doomsday", "cheat", "hack", "inject"
        ),
        [int]$MaxSuspiciousArgs = 0
    )

    function Draw-Separator {
        Write-Host "==================================================" -ForegroundColor DarkGray
    }

    Write-Host -ForegroundColor Red " ██████╗  ██████╗    ██╗     ███████╗ █████╗ ██████╗ ███╗   ██╗"
    Write-Host -ForegroundColor Red "██╔═══██╗██╔═══██╗   ██║     ██╔════╝██╔══██╗██╔══██╗████╗  ██║"
    Write-Host -ForegroundColor Red "███████║███████║    ██║     █████╗  ███████║██████╔╝██╔████╔██║"
    Write-Host -ForegroundColor Red "╚═══██╔╝ ╚═══██╔╝   ██║     ██╔══╝  ██╔══██║██╔══██╗██║╚██╔╝██║"
    Write-Host -ForegroundColor Red "██████╔╝ ██████╔╝   ███████╗███████╗██║  ██║██║  ██║██║  ╚═╝ ██║"
    Write-Host -ForegroundColor Red "╚═════╝  ╚═════╝    ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝"
    Write-Host -ForegroundColor Red "[JAVAW SCANNER BY SS LEARN IT]"
    Draw-Separator
    Write-Host ""

    $overallSuspiciousCount = 0
    $suspiciousResults = @()
    $suspiciousIndex = 1

    Write-Host "🔬 FASE 1: Analisi in Tempo Reale (Argomenti Processo attivo)" -ForegroundColor White

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
            foreach ($arg in $ExplicitCheatArgs) {
                if ($commandLine -like "*$arg*") {
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
        if ($suspiciousResults.Count -eq 0) {
            Write-Host "  > Nessun argomento di lancio esplicito rilevato." -ForegroundColor Green
        }
    } else {
        Write-Host "  > Nessun processo '$ProcessName' in esecuzione." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "📂 FASE 2: Analisi Forense (Tracce su Disco e Cartelle Minecraft)" -ForegroundColor White
    $diskTracesFound = $false

    foreach ($path in $ExplicitCheatPaths) {
        $expandedPath = $ExecutionContext.InvokeCommand.ExpandString($path)
        if (Test-Path -Path $expandedPath) {
            $diskTracesFound = $true
            $overallSuspiciousCount += 5
            $baseName = Split-Path $expandedPath -Leaf
            $suspiciousResults += [PSCustomObject]@{
                Index = $suspiciousIndex++
                Tipo = "Installazione Locale / Traccia"
                Risultato = "Trovata traccia esplicita di cheat: **$baseName** in '$expandedPath'"
            }
        }
    }

    $scanFolders = @("mods", "resourcepacks", "libraries")
    $baseMinecraftPath = "$env:APPDATA\.minecraft"

    foreach ($folder in $scanFolders) {
        $targetPath = Join-Path $baseMinecraftPath $folder
        if (Test-Path $targetPath) {
            $files = Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $fileName = $file.Name.ToLower()
                foreach ($pattern in $SuspiciousFilePatterns) {
                    if ($fileName -like "*$pattern*") {
                        $diskTracesFound = $true
                        $overallSuspiciousCount += 3
                        $suspiciousResults += [PSCustomObject]@{
                            Index = $suspiciousIndex++
                            Tipo = "File Sospetto in '$folder'"
                            Risultato = "File sospetto rilevato: **$($file.Name)** in '$($file.DirectoryName)'"
                        }
                    }
                }
            }
        }
    }

    if (-not $diskTracesFound) {
        Write-Host "  > Nessuna traccia di installazione di client noti rilevata." -ForegroundColor Green
    }

    Write-Host ""
    Draw-Separator

    if ($overallSuspiciousCount -gt $MaxSuspiciousArgs) {
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
            Write-Host "- BAN IMMEDIATO dell'utente (Installazione/Iniezione di cheat esplicita)."
