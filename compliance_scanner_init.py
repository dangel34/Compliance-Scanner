import platform


def get_linux_flavor():
    info = {}
    with open("/etc/os-release") as f:
        for line in f:
            if "=" in line:
                key, value = line.split("=", 1)
                info[key] = value.strip('"')
    distro = info.get("ID")
    like = info.get("ID_LIKE", "")
    print(distro, like)

def os_scan():
    os_parent = platform.system().lower()
    if "win" in os_parent:
        return "windows"
    elif "darwin" in os_parent:
        return "mac"
    elif "linux" in os_parent:
        get_linux_flavor()


if __name__ == "__main__":
    os_scan()