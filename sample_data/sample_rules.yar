rule SuspiciousScript {
    meta:
        description = "Detects suspicious script patterns"
    strings:
        $a = "powershell" nocase
        $b = "cmd.exe" nocase
        $c = "WScript.Shell" nocase
    condition:
        any of them
}

rule MalwareString {
    meta:
        description = "Common malware strings"
    strings:
        $a = "This program cannot be run in DOS mode"
        $b = "CreateRemoteThread" nocase
        $c = "VirtualAllocEx" nocase
    condition:
        2 of them
}
