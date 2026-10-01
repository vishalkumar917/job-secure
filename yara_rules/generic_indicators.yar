/*
   Generic, defensive YARA rules for process-memory scanning (windows.vadyarascan).
   These are educational detection signatures. A match is an indicator for review,
   not proof of malicious activity. Severity is read from meta.severity.
*/

rule Reflective_Loader_Export_String
{
    meta:
        description = "Export name used by many reflective DLL loaders"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1620/"
    strings:
        $s1 = "ReflectiveLoader" ascii
    condition:
        $s1
}

rule PowerShell_Download_Cradle_Strings
{
    meta:
        description = "PowerShell download-cradle strings resident in memory"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $a = "DownloadString" ascii wide nocase
        $b = "Net.WebClient" ascii wide nocase
        $c = "Invoke-Expression" ascii wide nocase
    condition:
        $a and ($b or $c)
}

rule Shadow_Copy_Deletion_Command
{
    meta:
        description = "Command strings associated with deleting volume shadow copies (ransomware preparation)"
        severity = "high"
    strings:
        $a = "vssadmin delete shadows" ascii wide nocase
        $b = "shadowcopy delete" ascii wide nocase
        $c = "wbadmin delete catalog" ascii wide nocase
    condition:
        any of them
}

rule Encoded_PowerShell_Launcher
{
    meta:
        description = "Encoded PowerShell command line resident in memory"
        severity = "low"
    strings:
        $a = "powershell" ascii wide nocase
        $b = " -enc " ascii wide nocase
        $c = " -encodedcommand " ascii wide nocase
    condition:
        $a and ($b or $c)
}
