import platform


def get_linux_flavor():
    """
    Get the distro and similar flavor of Linux
    :return:
    """
    info = {}
    with open("/etc/os-release") as f:
        for line in f:
            if "=" in line:
                key, value = line.split("=", 1)
                info[key] = value.strip('"')
    distro = info.get("ID").strip(" ")
    id_like = info.get("ID_LIKE", "")
    return distro, id_like

def os_scan() -> str:
    """
    Returns the current operating system (windows, mac, linux, linux debian)
    :return:
    """
    os_parent = platform.system().lower()
    if "win" in os_parent:
        if "server" in platform.win32_ver():
            return "windows_server"
        else:
            return "windows_client"
    elif "darwin" in os_parent:
        return "mac"
    elif "linux" in os_parent:
        distro, id_like = get_linux_flavor()
        if "debian" in id_like:
            return "debian"
        else:
            return "linux" # Generalization
    else:
        return "other" # would like to raise error if happened

