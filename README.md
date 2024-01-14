# BAURPM
Basic Arch User Repository (AUR) Package Manager

A basic AUR helper that I wrote for personal use on my Archlinux system

## Disclaimer
This is a small personal project that is still a work in progress so not everything is implemented.
Also the code is not guaranteed to be high quality as it is just for a personal project.

I have uploaded this to github in case of someone wanting to use it and/or to properly develop it.

## Dependancies
The only dependancies is for python to be installed and 1 pip package: aiohttp

## Usage
Usage Layout is
```sh
./baurpm.py [command] [options]
```
To install a Package
```sh
./baurpm.py -I package-name
```
See `./baurpm.py -H` for more
