import platform


def get_linux_flavor():
    """
    Get the distro and similar flavor of Linux.
    Returns ('unknown', '') if /etc/os-release is missing or malformed.
    """
    info = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path) as f:
                for line in f:
                    if "=" in line:
                        key, value = line.split("=", 1)
                        info[key.strip()] = value.strip().strip('"')
            break
        except OSError:
            continue
    distro = (info.get("ID") or "unknown").strip()
    id_like = info.get("ID_LIKE", "")
    return distro, id_like

def os_scan() -> str:
    """
    Returns the current operating system (windows, mac, linux, linux debian)
    :return:
    """
    os_parent = platform.system().lower()
    if os_parent.startswith("win"):
        try:
            if "server" in platform.win32_edition().lower():
                return "windows_server"
        except AttributeError:
            pass
        return "windows_client"
    elif "darwin" in os_parent:
        return "mac"
    elif "linux" in os_parent:
        distro, id_like = get_linux_flavor()
        if distro == "debian" or "debian" in id_like:
            return "debian"
        else:
            return "linux" # Generalization
    else:
        return "other"  # would like to raise error if happened


def get_scanner():
    """
    Returns a scanner instance for the current OS, or None if unsupported.
    """
    os_type = os_scan()
    if "windows" in os_type:
        from core.scanners.windows import WindowsModule
        return WindowsModule()
    if "debian" in os_type:
        from core.scanners.debian import DebianModule
        return DebianModule()
    return None

