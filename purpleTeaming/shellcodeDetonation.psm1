<#
.Module Name
    ShellcodeDetonation
.SYNOPSIS
    Analyzes and executes raw binary (.bin) shellcode.
.DESCRIPTION
    1. Measures Entropy to distinguish 'Encrypted Data' from 'Code'.
    2. Uses P/Invoke to allocate memory and execute valid shellcode.
#>

Function Get-FileEntropy {
    param([string]$FilePath)
    $Bytes = Get-Content $FilePath -Encoding Byte -ReadCount 0
    if (-not $Bytes) { return 0 }
    
    $Frequency = @{}
    $Bytes | ForEach-Object { $Frequency[$_]++ }
    
    $Entropy = 0.0
    $Len = $Bytes.Count
    foreach ($Count in $Frequency.Values) {
        $P = $Count / $Len
        $Entropy -= $P * [Math]::Log($P, 2)
    }
    return $Entropy
}

Function Invoke-ShellcodeDetonation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SamplesDir
    )

    $Confirm = Read-Host "WARNING: This executes RAW SHELLCODE in memory. This can crash the PowerShell process. Type 'YES' to proceed"
    if ($Confirm -ne "YES") { return }

    if (-not (Test-Path $SamplesDir)) { Write-Error "Dir not found"; return }
    $BinFiles = Get-ChildItem -Path $SamplesDir -Filter "*.bin"

    Write-Host "Analyzing $($BinFiles.Count) binary files..." -ForegroundColor Yellow

    # --- C# SHELLCODE RUNNER ---
    $Code = @"
    using System;
    using System.Runtime.InteropServices;

    public class Shellcode {
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void Run(byte[] shellcode) {
            IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x1000, 0x40);
            Marshal.Copy(shellcode, 0, funcAddr, shellcode.Length);
            
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, funcAddr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 5000); // Wait 5 seconds max to prevent hang
        }
    }
"@
    Add-Type -TypeDefinition $Code -Language CSharp

    foreach ($File in $BinFiles) {
        $Path = $File.FullName
        $Entropy = Get-FileEntropy -FilePath $Path
        $Size = $File.Length
        
        # --- ANALYSIS ---
        # 1. Check for NOP Sleds (0x90 repeated)
        $Bytes = Get-Content $Path -Encoding Byte -TotalCount 50
        $Hex = ($Bytes | ForEach-Object { $_.ToString("X2") }) -join ""
        $HasNops = $Hex -match "909090"
        
        # 2. Decision Logic
        $Type = "Unknown"
        $Action = "Skip"

        if ($Entropy -gt 7.2) {
            $Type = "High Entropy (Encrypted/Compressed)"
            $Action = "Skip"
        } elseif ($Entropy -lt 4.0) {
            $Type = "Low Entropy (Text/Padding)"
            $Action = "Skip"
        } else {
            # Mid Entropy is usually Code
            $Type = "Likely Shellcode"
            $Action = "DETONATE"
        }

        if ($HasNops) { $Type = "Shellcode (NOPs Detected)"; $Action = "DETONATE" }

        Write-Host "File: $($File.Name)" -NoNewline
        Write-Host " [Entropy: $([Math]::Round($Entropy, 2))]" -NoNewline -ForegroundColor Cyan
        
        if ($Action -eq "DETONATE") {
            Write-Host " -> $Type -> EXECUTING..." -ForegroundColor Green
            try {
                $RawBytes = Get-Content $Path -Encoding Byte -ReadCount 0
                [Shellcode]::Run($RawBytes)
                Write-Host "    [+] Execution triggered (Thread Created)" -ForegroundColor Green
            } catch {
                Write-Host "    [!] Crash/Fail: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host " -> $Type -> Skipped" -ForegroundColor Gray
        }
    }
}
Export-ModuleMember -Function Invoke-ShellcodeDetonation