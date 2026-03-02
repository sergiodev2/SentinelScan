rule Suspicious_Download_Strings
{
  meta:
    author = "SentinelScan"
    description = "Detects suspicious download-related strings"
  strings:
    $a = "powershell" nocase
    $b = "bitsadmin" nocase
    $c = "curl " nocase
    $d = "wget " nocase
    $e = "Invoke-WebRequest" nocase
  condition:
    2 of them
}

rule Suspicious_Execution_Strings
{
  meta:
    author = "SentinelScan"
    description = "Detects suspicious execution-related strings"
  strings:
    $a = "cmd.exe" nocase
    $b = "/bin/sh" nocase
    $c = "CreateRemoteThread" nocase
    $d = "VirtualAlloc" nocase
    $e = "WriteProcessMemory" nocase
  condition:
    2 of them
}