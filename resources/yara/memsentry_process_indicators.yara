/* Conservative triage indicators. Matches are leads, not malware verdicts. */

rule MemSentry_Windows_PowerShell_Encoded
{
    meta:
        description = "PowerShell command text with an encoded-command switch"
        platform = "windows"
        confidence = "low"
    strings:
        $powershell = "powershell" nocase ascii wide
        $encoded_short = " -e " nocase ascii wide
        $encoded_long = "-encodedcommand" nocase ascii wide
    condition:
        $powershell and ($encoded_short or $encoded_long)
}

rule MemSentry_Unix_Suspicious_Shell_Command
{
    meta:
        description = "Unix shell command text containing a downloader utility"
        platform = "linux,macos"
        confidence = "low"
    strings:
        $shell = "/bin/sh" ascii wide
        $bash = "/bin/bash" ascii wide
        $curl = "curl " nocase ascii wide
        $wget = "wget " nocase ascii wide
    condition:
        ($shell or $bash) and ($curl or $wget)
}

rule MemSentry_Credential_Access_Tool_Indicator
{
    meta:
        description = "Known credential-dumping tool name in memory"
        platform = "windows,linux,macos"
        confidence = "low"
    strings:
        $mimikatz = "mimikatz" nocase ascii wide
        $rubeus = "rubeus" nocase ascii wide
        $laZagne = "laZagne" nocase ascii wide
    condition:
        1 of them
}
