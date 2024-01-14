#!/bin/bash
# The Earliest Version of baurpm was written in bash
echo "Basic Arch User Repository Package Manager v1.0a"
if [ -z "$1" ]
    then
        echo -e "\033[1;31mERROR:\033[0m No arguments were provided!\nTry \033[1m$(basename $0) -H\033[0m or \033[1m$(basename $0) --help\033[0m for a list of commands"
        exit 1
    fi

USERNAME=$USER
if [ $UID == 0 ]
then
    if [ -z $SUDO_USER ]
    then
        USERNAME="nobody"
    else
        USERNAME=$SUDO_USER
    fi
fi

find_pkg () {
    if [ -z "$1" ]
    then
        echo -e "\033[1;31mERROR:\033[0m No package name was provided to search for!"
        return 1
    fi
    local PKG_FND=$(git ls-remote "https://aur.archlinux.org/${1}.git")
    if [ -z "$PKG_FND" ]
    then
        echo -e "\033[1;31mERROR:\033[0m Package \033[1m${1}\033[0m not found!"
        return 1
    fi
}

download_pkg () {
    sudo -u $USERNAME mkdir -p /tmp/install-aur
    rm -rf /tmp/install-aur/*
    cd /tmp/install-aur
    sudo -u $USERNAME git clone "https://aur.archlinux.org/${1}.git"
    return $?
}

update_check () {
    QM_OUTPUT=$(pacman -Qm)
    IFS=$'\n' PKG_LIST=($QM_OUTPUT)
    echo -e "Checking \033[1m${#PKG_LIST[@]}\033[0m packages..."
    PKG_QUERIES=""
    for pkg in "${PKG_LIST[@]}"
    do
        PKG_QUERIES+="&arg[]=${pkg% *}"
    done
    # echo "https://aur.archlinux.org/rpc/?v=5&type=info${PKG_QUERIES}"
    CURL_OUTPUT=$(curl -s "https://aur.archlinux.org/rpc/?v=5&type=info${PKG_QUERIES}" | jq -r '.results[] | "\(.Name) \(.Version)"')
    IFS=$'\n' LATEST_PKGS=($CURL_OUTPUT)
    TO_UPDATE=()
    for pkg in "${LATEST_PKGS[@]}"
    do
        for current_pkg in "${PKG_LIST[@]}"
        do
            if [ "${pkg% *}" == "${current_pkg% *}" ]
            then
                if [ "${pkg#* }" != "${current_pkg#* }" ]
                then
                    TO_UPDATE+=("${pkg% *}")
                fi
            fi
        done
    done
    echo -e "\033[1m${#TO_UPDATE[@]}\033[0m aur packages can be updated:\n\033[32m${TO_UPDATE[@]}\033[0m"
}

if [ $1 == "-H" ] || [ $1 == "--help" ]
then
    echo -e "List of available commands:\n -I\tInstall a package\n -C\tCheck installed packages for newer versions and update them\n -F\tFind a package\n -G\tGet information on a package"
    exit 0
elif [ $1 == "-C" ]
then
    update_check
    exit 0
elif [ $1 == "-F" ]
then
    find_pkg $2
    if [ $? == 0 ]
    then
        echo -e "A package called \033[1m${2}\033[0m was found.\nUse \033[1m$(basename $0) -G\033[0m to get more information on this package or \033[1m-I\033[0m to install"
        exit 0
    else
        exit 1
    fi
elif [ $1 == "-G" ]
then
    find_pkg $2
    if [ $? != 0 ]
    then
        exit 1
    fi
    echo -ne "A package called \033[1m${2}\033[0m was found.\nView PKGBUILD? [Y/n]: "
    read RAW_RESP
    RESP=$(echo "$RAW_RESP" | tr '[:upper:]' '[:lower:]')
    if ! [[ $RESP = y* ]]
    then
        echo "Cancelling installation..."
        exit 0
    fi
    download_pkg $2
    if [ $? != 0 ]
    then
        exit 1
    fi
    cd $2
    cat PKGBUILD | less
    cd
    rm -rf /tmp/install-aur
    exit 0

elif [ $1 == "-I" ]
then
    PKGNAME=$2
    find_pkg $PKGNAME
    if [ $? != 0 ]
    then
        exit 1
    fi
    echo -ne "A package called \033[1m${PKGNAME}\033[0m was found.\nCompile and install the package? [Y/n]: "
    read RAW_RESP
    RESP=$(echo "$RAW_RESP" | tr '[:upper:]' '[:lower:]')
    if ! [[ $RESP = y* ]]
    then 
        echo "Cancelling installation..."
        exit 0
    fi
    download_pkg $PKGNAME
    if [ $? != 0 ]
    then
        exit 1
    fi
    cd $PKGNAME
    echo -e "Package Downloaded with the following files:"
    ls
    echo -ne "View and edit the PKGBUILD? [Y/n]: "
    read RAW_RESP
    RESP=$(echo "$RAW_RESP" | tr '[:upper:]' '[:lower:]')
    if [[ $RESP = y* ]]
    then
        if [ -z "$EDITOR" ]
        then
            if [ -x "$(command -v nano)" ]
            then
                nano PKGBUILD
            elif [ -x "$(command -v vi)" ]
            then
                vi PKGBUILD
            else
                echo "No installed editor was found"
            fi
        else
            if [ -x "$(command -v $EDITOR)" ]
            then
                $EDITOR PKGBUILD
            else
                echo "No installed editor was found"
            fi
            echo -n
        fi
        echo -ne "Continue to compile and install the package? [Y/n]: "
        read RAW_RESP
        RESP=$(echo "$RAW_RESP" | tr '[:upper:]' '[:lower:]')
        if ! [[ $RESP = y* ]]
        then 
            echo "Cancelling installation..."
            exit 0
        fi
    fi
    RAW_DEPENDS=($(sudo -u $USERNAME makepkg --printsrcinfo | grep $'\tdepends' | sed $'s/\tdepends = //g' | tr '\n' ' '))
    AUR_DEPENDS=()
    for DEPENDANT in "${RAW_DEPENDS[@]}"
    do
        pacman -Ss $DEPENDANT > /dev/null 2>&1
        if [ $? == 1 ]
        then
            AUR_DEPENDS+=("$DEPENDANT")
        fi
    done
    if [ "${#AUR_DEPENDS[@]}" -gt 0 ]
    then
        echo -e "The following dependencies are AUR packages and therefore cannot be installed with pacman directly:"
        echo "\033[32m${AUR_DEPENDS[@]}\033[0m"
        echo -e "Try installing these packages first with \033[1m$(basename $0) -I\033[0m and just compile with makepkg -d if there is any circular depencencies"
        exit 1
    fi
    sudo -u $USERNAME makepkg -s
    MAKEPKG_STATUS=$?
    if [ $MAKEPKG_STATUS != 0 ]
    then
        echo -e "\033[1;31mERROR:\033[0m Makepkg command failed with exit code \033[1m${MAKEPKG_STATUS}\033[0m!"
        cd
        rm -rf /tmp/install-aur
        exit 1
    fi
    if [ $UID == 0 ]
    then
        pacman -U *.pkg.tar.zst
    else
        sudo pacman -U *.pkg.tar.zst
    fi
    cd
    rm -rf /tmp/install-aur
else
    echo -e "\033[1;31mERROR:\033[0m command \033[1m${1}\033[0m not reconised!\nTry \033[1m-H\033[0m or \033[1m--help\033[0m for a list of commands"
    exit 1
fi
