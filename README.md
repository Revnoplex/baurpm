# BAURPM
Basic Arch User Repository (AUR) Package Manager

A basic AUR helper written in python that I wrote for personal use on my Archlinux system.

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

Running make by itself should generate `build/baurpm`
```sh
make
```

You can build debug binaries with
```sh
make -B baurpm_debug
```
This creates `build/baurpm-debug`

You can install with
```sh
sudo make install
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

See `./baurpm.py -H` for more commands and usage
