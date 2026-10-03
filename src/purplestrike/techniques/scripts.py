"""Quoting helpers for remote simulation scripts."""


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def delete_temp_files(*names: str) -> str:
    """Delete exact files, including Windows TEMP paths containing 8.3 aliases."""
    return "; ".join(
        f"[IO.File]::Delete((Join-Path $env:TEMP {ps_quote(name)}))" for name in names
    )


def registry_path(value: str) -> str:
    for hive in ("HKLM", "HKCU", "HKCR", "HKU", "HKCC"):
        if value.upper().startswith(hive + "\\"):
            return hive + ":\\" + value[len(hive) + 1:]
    return value


def ldap_directory_entry(container: str = "") -> str:
    from purplestrike.techniques.connection import _get_credential

    domain = _get_credential("TARGET_AD_DOMAIN", "")
    if not domain:
        raise ValueError("An AD domain is required for this technique")
    username = _get_credential("TARGET_USERNAME", "")
    if "\\" not in username and "@" not in username:
        username = f"{domain}\\{username}"
    password = _get_credential("TARGET_PASSWORD", "")
    base = ",".join(f"DC={part}" for part in domain.split("."))
    if container:
        base = container + "," + base
    return (
        "$de = New-Object System.DirectoryServices.DirectoryEntry("
        f"{ps_quote('LDAP://' + domain + '/' + base)}, "
        f"{ps_quote(username)}, {ps_quote(password)}); "
    )
