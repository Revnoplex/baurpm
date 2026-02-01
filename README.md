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

## Dependencies for C version:
See [pkglist.txt](pkglist.txt)

This is an AUR Helper so this will only run on arch based systems.

## Building The C Version.

Make sure all dependencies are installed
```sh
sudo pacman -S --needed - < pkglist.txt
```

Then run these commands to compile the program.
```sh
autoreconf --install
./configure
make
```
This should generate the execuable `baurpm`. You can then install this executable to PATH with
```sh
sudo make install
```

### Debug Build

You can build debug binaries with
```sh
make -B baurpm_debug -f Makefile.2
```
This creates `build/baurpm-debug`

## Usage
Usage Layout is
```sh
baurpm [command] [options]
```
To install a Package
```sh
baurpm -I package-name
```
To upgrade installed aur packages
```sh
baurpm -C
```

Use `./baurpm.py` to use the python version

See `./baurpm.py -H` for more commands and usage
