![C](https://img.shields.io/badge/-C-ffffff?style=for-the-badge&logo=c)
![CURL](https://img.shields.io/badge/-CURL-0a3754?style=for-the-badge&logo=curl)
![cJSON](https://img.shields.io/badge/-cJSON-000000?style=for-the-badge&logo=json)

# BAURPM
Basic Arch User Repository (AUR) Package Manager

A basic AUR helper written in python (rewriting in c) that I wrote for personal use on my Archlinux system.

## Disclaimer
This is a small personal project that is still a work in progress so not everything is implemented.
Also, the code is not guaranteed to be high quality as it is just for a personal project.

I have uploaded this to GitHub in case of someone wanting to use it and/or to properly develop it. 
The main reason is so I can easily install or update it on any of my archlinux installations.

## Dependencies for python version.
- python 3.8 or later
- sudo

## Dependencies for c version:
- curl
- cjson
- libarchive
- sudo

This is an AUR Helper so this will only run on arch based systems.

## Building The C Version.

make sure all dependencies are installed
```sh
sudo pacman -S --needed - < pkglist.txt
```

Then run these commands to compile the program.
```sh
autoreconf --install
./configure
make
```
This should generate `baurpm`

You can build debug binaries with
```sh
make -B baurpm_debug -f Makefile.2
```
This creates `build/baurpm-debug`

You can install to PATH with
```sh
sudo make install
```

### Old Method

Running make by itself should generate `build/baurpm`
```sh
make -f Makefile.2
```

You can install with
```sh
sudo make install -f Makefile.2
```

## Usage
Usage Layout is
```sh
./baurpm.py [command] [options]
```
To install a Package
```sh
./baurpm.py -I package-name
```
To upgrade installed aur packages
```sh
./baurpm.py -C
```

Use `./baurpm` to use the c version

See `./baurpm.py -H` for more commands and usage
