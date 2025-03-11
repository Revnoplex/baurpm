#!/usr/bin/env python3
import datetime
import inspect
import json
import pathlib
import shutil
import subprocess
import sys
import os
import time
from typing import Union
import urllib.request
import urllib.error
import http.client

LONG_NAME = "Basic Arch User Repository (AUR) Package Manager"
__title__ = "baurpm"
__version__ = "1.0.0a"
__author__ = "Revnoplex"
__license__ = "MIT"
__copyright__ = f"Copyright (c) 2022-2025 {__author__}"


class BAURPMException(BaseException):
    pass


class PackageNotFound(BAURPMException):
    def __init__(self, missing_packages: list[str]):
        self.missing_packages = missing_packages
        self.message = f"The following packages could not be found: {', '.join(missing_packages)}"
        super().__init__(self.message)


class UnexpectedReturnType(BAURPMException):
    def __init__(self, expected_type: object, returned_type: object):
        self.expected_type = expected_type
        self.returned_type = returned_type
        super().__init__(f"Expected a {self.expected_type} object, got a {self.returned_type} object instead.")


class UnexpectedContentType(BAURPMException):
    def __init__(self, expected_type: str, returned_type: str):
        self.expected_type = expected_type
        self.returned_type = returned_type
        super().__init__(f"Expected a {self.expected_type} response, got a {self.returned_type} response instead.")


class HTTPException(BAURPMException):
    """Exception that's raised when an HTTP request operation fails.
    Args:
        response (http.client.HTTPResponse): The response associated with the error
        message (str): The error message associated with the error that the RPC interface gave
        error_data (dict): The raw error data associated with the error
    Attributes:
        response (http.client.HTTPResponse): The response associated with the error
        message (str): The error message associated with the error that the RPC interface gave
        status (int): The HTTP status code associated with the error
        error_data (dict): The raw error data associated with the error
        """
    def __init__(self, response: http.client.HTTPResponse, message: str = None, error_data: dict = None):
        self.response = response
        self.error_data = error_data
        self.message = message
        self.status = response.status
        self.text: str = f': {message}' if message else ""
        super().__init__(f'{self.status} {self.response.reason}{self.text}')


class AURWebRTCError(BAURPMException):
    def __init__(self, response: http.client.HTTPResponse, data: dict):
        self.response = response
        self.data = data
        self.status = response.status
        self.message = data.get("error")
        self.text = self.message or ""
        self.http_exception = f"{self.status} {self.response.reason}: " if self.status != 200 else ""
        super().__init__(f"{self.http_exception}{self.text}")


def byte_units(bytes_size: int, iec=False) -> str:
    """Converts large byte numbers to SI units.
    Args:
        bytes_size (int): the number (bytes)
        iec (bool): whether to use iec units (2^10, 2^20, 2^30, etc. bytes) or si units (10^3, 10^6, 10^9, etc. bytes)
    Returns:
        str: the bytes in the appropriate SI Units"""
    units_in = 2**10 if iec else 10**3
    unit_names = ['bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'] if iec else \
        ['bytes', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    rounded = ""
    for ex_multiplier, unit in enumerate(unit_names):
        multiplier = units_in**ex_multiplier
        if bytes_size >= units_in ** 9:
            unit = "YB"
            multiplier = units_in ** 8
        if bytes_size < units_in**(ex_multiplier+1) or bytes_size >= units_in**9:
            if unit == 'bytes':
                unit = 'byte' if bytes_size == 1 else unit
                rounded = f'{bytes_size} {unit}'
            else:
                formatted_size: float = round(float(bytes_size) / multiplier, 3)
                rounded = f'{formatted_size} {unit}'
                decimal_place = f' {unit}' if formatted_size.is_integer() else "." + rounded.split(".")[1]
                rounded = "{:,}".format(int(rounded.split(".")[0])) + decimal_place
            break
    return rounded


def bit_units(bit_size: int, iec=False) -> str:
    """Converts large bit numbers to SI units.
    Args:
        bit_size (int): the number (bytes)
        iec (bool): whether to use iec units (2^10, 2^20, 2^30, etc. bits) or si units (10^3, 10^6, 10^9, etc. bits)
    Returns:
        str: the bytes in the appropriate SI Units"""
    units_in = 2**10 if iec else 10**3
    unit_names = ['bits', 'Kibit', 'Mibit', 'Gibit', 'Tibit', 'Pibit', 'Eibit', 'Zibit', 'Yibit'] if iec else \
        ['bits', 'kbit', 'Mbit', 'Gbit', 'Tbit', 'Pbit', 'Ebit', 'Zbit', 'Ybit']
    rounded = ""
    for ex_multiplier, unit in enumerate(unit_names):
        multiplier = units_in**ex_multiplier
        if bit_size >= units_in ** 9:
            unit = "YB"
            multiplier = units_in ** 8
        if bit_size < units_in**(ex_multiplier+1) or bit_size >= units_in**9:
            if unit == 'bytes':
                unit = 'byte' if bit_size == 1 else unit
                rounded = f'{bit_size} {unit}'
            else:
                formatted_size: float = round(float(bit_size) / multiplier, 3)
                rounded = f'{formatted_size} {unit}'
                decimal_place = f' {unit}' if formatted_size.is_integer() else "." + rounded.split(".")[1]
                rounded = "{:,}".format(int(rounded.split(".")[0])) + decimal_place
            break
    return rounded


class BAURPMUtils:
    def __init__(self, api_version: str = '5', api_timeout: float = 10):
        self.api_version = api_version
        self.official_base_url = "https://www.archlinux.org/packages"
        self.aur_base_url = "https://aur.archlinux.org"
        self.aur_api_base_url = f"{self.aur_base_url}/rpc?v={api_version}"
        self.api_timeout = api_timeout

    def find_official_pkg(self, package_name: str) -> Union[dict, str]:
        """Fetches package info from the official database

        Basic Information

        Args:
            package_name (str): The package to get the information of
        Returns:
            Union[dict, str]: The information of the found packages
        Raises:
            PackageNotFound: The api could not get information for one of the packages provided
            HTTPException: The api experienced an error
            UnexpectedContentType: The api returned an unexpected response
            json.JSONDecodeError: An error occurred decoding the response from the api
            urllib.error.URLError: There was a problem sending the request to the api
            TimeoutError: The request sent to the api timed out
        """
        found_package = None
        with urllib.request.urlopen(f'{self.official_base_url}/search/json/?name={package_name}',
                                    timeout=self.api_timeout) as response:
            response: http.client.HTTPResponse
            if response.status >= 400:
                raise HTTPException(response)
            if response.getheader("Content-Type") == "application/json":
                response_content = json.load(response)
                if response_content.get("results") and len(response_content["results"]) > 0:
                    found_package = response_content["results"][0]
            else:
                raise UnexpectedContentType("application/json", response.getheader("Content-Type"))
        if found_package is None:
            raise PackageNotFound([package_name])
        return found_package

    def find_pkg(self, package_names: list[str], ignore_missing=False):
        """Fetches package info from the aur database

        Basic Information

        Args:
            package_names (list[str]): The packages to get the information of
            ignore_missing (bool): Ignore missing packages
        Returns:
            list[dict]: The information of the found packages
        Raises:
            PackageNotFound: The api could not get information for one of the packages provided
            AURWebRTCError: The api returned an informational error
            HTTPException: The api experienced an error
            UnexpectedContentType: The api returned an unexpected response
            json.JSONDecodeError: An error occurred decoding the response from the api
            urllib.error.URLError: There was a problem sending the request to the api
            TimeoutError: The request sent to the api timed out
        """
        url_args = "".join(["&arg[]=" + package for package in package_names])
        with urllib.request.urlopen(f"{self.aur_api_base_url}&type=info{url_args}",
                                    timeout=self.api_timeout) as response:
            response: http.client.HTTPResponse
            if response.getheader("Content-Type") == "application/json":
                api_data = json.load(response)
                if response.status >= 400:
                    if api_data["type"] == "error":
                        raise AURWebRTCError(response, api_data)
                    else:
                        raise HTTPException(response, error_data=api_data)
                else:
                    if api_data["type"] == "error":
                        raise AURWebRTCError(response, api_data)
                    found_packages: list[dict] = api_data["results"]
                    found_packages_names = [package["Name"] for package in found_packages]
                    missing_packages = list(set(package_names) - set(found_packages_names))
                    if len(missing_packages) > 0 and not ignore_missing:
                        raise PackageNotFound(missing_packages)
                    else:
                        return found_packages
            elif response.status >= 400:
                raise HTTPException(response)
            else:
                raise UnexpectedContentType("application/json", response.getheader("Content-Type"))

    @staticmethod
    def speed_calc(downloaded_bytes, start_time):
        speed = bit_units(round(downloaded_bytes / (time.perf_counter() - start_time)) * 8)
        return speed

    def download_pkg(self, url_path: str, to: pathlib.Path) -> str:
        """Fetches package info from the aur database

                Basic Information

                Args:
                    url_path (str): The path to the file of the package to download on the server
                    to (pathlib.Path): Where to save the download
                Returns:

                Raises:
                    HTTPException: The api experienced an error
                    urllib.error.URLError: There was a problem sending the request to the api
                    TimeoutError: The request sent to the api timed out
                """
        to.mkdir(parents=True, exist_ok=True)
        filename = pathlib.Path(url_path).name
        api_netloc = self.aur_base_url.replace('/', '').replace('https:', '')
        if os.path.exists(f'{to.absolute()}/{filename}'):
            print(f"Using already downloaded {filename}")
            return f"{to.absolute()}/{filename}"
        print(f"\rConnecting to {api_netloc}", end="")
        with urllib.request.urlopen(self.aur_base_url + url_path, timeout=self.api_timeout) as response:
            response: http.client.HTTPResponse
            if response.status >= 400:
                raise HTTPException(response)
            else:
                print(f"\rDownloading {filename} from {api_netloc}", end="")
                with open(f'{to.absolute()}/{filename}', "wb") as download_file:
                    downloaded_bytes = 0
                    chunk_size = 2 ** 10
                    start_time = time.perf_counter()
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        downloaded_bytes += len(chunk)
                        download_file.write(chunk)
                        del chunk
                        speed = self.speed_calc(downloaded_bytes, start_time)
                        print(f"\rDownloading {filename} ({byte_units(downloaded_bytes, True).ljust(12)})"
                              f" from {api_netloc} at {speed}/s   ", end="")
                    print(f"\rDownloaded {filename} ({byte_units(downloaded_bytes, True)}) from "
                          f"{api_netloc} in {datetime.timedelta(seconds=time.perf_counter() - start_time)} "
                          f"seconds")
                    return f"{to.absolute()}/{filename}"

    @staticmethod
    def fetch_initramfs_mod_times() -> dict[str, float] | dict:
        mod_times = {}
        for module in pathlib.Path("/usr/lib/modules/").glob("*/pkgbase"):
            with open(module, "r") as preset_name_file:
                preset_name = preset_name_file.read().strip()
            with open(f"/etc/mkinitcpio.d/{preset_name}.preset") as presets_file:
                preset_names = []
                for line in presets_file.read().splitlines():
                    if line.lower().startswith("presets="):
                        for preset in line.split("=")[1].strip("()").split(" "):
                            preset_names.append(preset.strip("'\""))
                    if line.split("_image=")[0] in preset_names:
                        image_path = line.split("_image=")[1].strip("'\"")
                        mod_times[image_path] = os.stat(image_path).st_mtime
        return mod_times

    def git_clone_pkg(self, pkg_base_name: str, to: pathlib.Path) -> bool:
        full_directory = to.expanduser().absolute()
        process = subprocess.Popen(
            ["git", "-C", str(full_directory), "clone", f"{self.aur_base_url}/{pkg_base_name}.git"],
            stderr=subprocess.PIPE
        )
        stderr_output = process.stderr.read().splitlines()
        already_cloned_str = (
            f"fatal: destination path '{pkg_base_name}' already exists and is not an empty directory."
        )
        if process.wait() == 128 and stderr_output[0].decode("utf-8") == already_cloned_str:
            return True
        elif process.poll():
            raise BAURPMException(f"Git clone failed with exit code {process.poll()}.")
        return False

    @staticmethod
    def git_pull_pkg(pkg_base_name: str, to: pathlib.Path):
        full_directory = to.expanduser().absolute()
        process = subprocess.Popen(
            ["git", "-C", f"{full_directory}/{pkg_base_name}", "pull"],
            stderr=subprocess.PIPE
        )
        if process.wait():
            raise BAURPMException(f"Git pull failed with exit code {process.poll()}.")


class BAURPMCommands:
    def __init__(self):
        self.utils = BAURPMUtils()

    def command_h(self, *args):
        """displays this message
        
        Usage:
            {name} [command-name]
        Options:
            None
        """
        raw_class = dir(self)
        cmds = [obj for obj in raw_class if not obj.startswith('__')]
        if args[1]:
            found_command = None
            for cmd in cmds:
                if cmd.startswith('command_') and cmd[-1] == args[1][0].lower():
                    found_command = getattr(self, cmd)
            if found_command:
                cmd_letter = found_command.__name__[-1].upper()
                if found_command.__doc__:
                    clean_doc = "\n".join(
                        [line for line in inspect.cleandoc(found_command.__doc__).splitlines() if line]
                    )
                    print(f"{cmd_letter}: " + clean_doc.format(name=f"baurpm -{cmd_letter}"))
                    if len(clean_doc.splitlines()) < 2:
                        print("No usage or options are documented for this command")
                else:
                    print(f"{cmd_letter}: **No Documentation**")
            else:
                print(f"No command by the name of {args[1][0]}")
        else:
            print(f"Usage: {__title__} [command][options] [arguments]")
            print("Executable commands:")
            for cmd in cmds:
                cmd_attr = getattr(self, cmd)
                if callable(cmd_attr):
                    doc = (cmd_attr.__doc__ or "**No Description**").replace("\n\n", "\n").splitlines()
                    description = doc[0] or "**No Description**"
                    print(f' -{cmd[-1].upper()}\t{description}')
            print(f"use {__title__} -H [command-name] for help with that command")

    def command_g(self, *args):
        """Get info on an AUR package

        Usage:
            {name} [package]
        Options:
            None
        """
        print(f"Searching for \x1b[1m{', '.join(args[1])}\x1b[0m")
        try:
            package_data = self.utils.find_pkg(args[1])
        except PackageNotFound as error:
            print(error.message)
            return
        except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                TimeoutError) as error:
            print(f"An error occurred while getting information on the package/s: {str(error)}")
            return
        package_names = [package["Name"] for package in package_data]
        if len(package_names) < 2:
            found_message = f"A package called \033[1m{package_names[0]}\033[0m was found."
        else:
            found_message = f"Some packages called \033[1m{', '.join(package_names)}\033[0m were found."
        print(f"{found_message}")
        for package in package_data:
            try:    
                prompt = input(f"View information for {package['Name']}? [y/n]: ")
                if prompt.lower().startswith("y"):
                    space_size = 0
                    for name, _ in package.items():
                        if len(name) > space_size:
                            space_size = len(name)
                    output = ""
                    for name, value in package.items():
                        if isinstance(value, list):
                            value = ", ".join(value)
                        if name in ["FirstSubmitted", "LastModified"]:
                            vtime = datetime.datetime.fromtimestamp(value if isinstance(value, (int, float)) else 0)
                            value = vtime.strftime(f"%A, %B %d %Y, %H:%M:%S (local time)")
                        output += f'\n{name}:{" "*(space_size + 4 - len(name))}{value}'
                    print(output)
                    prompt = input("Download and view build files and PKGBUILD? [y/n]: ")
                    if prompt.lower().startswith("y"):
                        snapshot_url: str = package["URLPath"]
                        snapshot_url = f'{pathlib.Path(snapshot_url).parents[0]}/{package["PackageBase"]}' \
                                        f'{"".join(pathlib.Path(snapshot_url).suffixes)}'
                        try:
                            filename = \
                                self.utils.download_pkg(snapshot_url, pathlib.Path(f"/tmp/baurpm/cache"))
                        except (HTTPException, urllib.error.URLError, TimeoutError) as err:
                            print(f"An error occurred while downloading the package/s: {str(err)}")
                            return
                        shutil.unpack_archive(filename, f"/tmp/baurpm/")
                        package_name = package["PackageBase"]
                        print(f"Build files for \033[1m{package_name}\033[0m are:"
                                f"\n     {' '.join(os.listdir(f'/tmp/baurpm/{package_name}'))}")
                        input("Press Enter to continue and view PKGBUILD")
                        viewing_process = subprocess.Popen(
                            ["less", f"/tmp/baurpm/{package_name}/PKGBUILD"], stderr=subprocess.PIPE
                        )
                        viewing_failed = viewing_process.wait()
                        if viewing_failed:
                            print(
                                f"\033[1;33mWarning\033[0m: Viewing package info failed with exit code "
                                f"{viewing_failed}: {viewing_process.stderr.read().decode('utf-8')}"
                            )
                        deletion_process = subprocess.Popen(
                            ["rm", "-rf", "/tmp/baurpm"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE
                        )
                        deletion_failed = deletion_process.wait()
                        if deletion_failed:
                            print(
                                f"\033[1;31mFatal\033[0m: Deleting build files failed with exit code "
                                f"{deletion_failed}: {deletion_process.stderr.read().decode('utf-8')}"
                            )
            except (KeyboardInterrupt, EOFError, SystemExit):
                print()
                break

    def command_i(self, *args, **kwargs):
        """Install an AUR package without keeping the download

        Usage:
            {name}[options] [package(s)]
        Options:
            f: Ignore any missing packages
            n: Skip Reading PKGBUILD files
        """
        if not kwargs.get('package_data'):
            print(f"Searching for \x1b[1m{', '.join(args[1])}\x1b[0m")
            try:
                package_data = self.utils.find_pkg(args[1])
            except PackageNotFound as error:
                if "f" in args[0]:
                    stripped_packages = [raw_pkg for raw_pkg in args[1] if raw_pkg not in error.missing_packages]
                    try:
                        package_data = self.utils.find_pkg(stripped_packages)
                    except PackageNotFound as error:
                        print(error.message)
                        return
                else:
                    print(error.message)
                    return
            except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                    TimeoutError) as error:
                print(f"An error occurred while getting information on the package/s: {str(error)}")
                return
            package_names = [package["Name"] for package in package_data]
            if len(package_names) < 2:
                found_message = f"A package called \033[1m{package_names[0]}\033[0m was found." \
                                f"\nMake and install the package?"
            else:
                found_message = f"Some packages called \033[1m{', '.join(package_names)}\033[0m were found." \
                               f"\nMake and install the packages?"
            raw_response = input(f"{found_message} [Y/n]: ")
            if not raw_response.lower().startswith("y"):
                print("aborting...")
                return
        else:
            package_data = kwargs["package_data"]
            package_names = [package["Name"] for package in package_data]
        bases = []
        for package in package_data:
            snapshot_url: str = package["URLPath"]
            if package["Name"] != package["PackageBase"]:
                if package["PackageBase"] not in bases:
                    bases.append(package["PackageBase"])
                else:
                    continue
                snapshot_url = f'{pathlib.Path(snapshot_url).parents[0]}/{package["PackageBase"]}' \
                               f'{"".join(pathlib.Path(snapshot_url).suffixes)}'
            try:
                filename = \
                    self.utils.download_pkg(snapshot_url, pathlib.Path(f"/tmp/baurpm/cache"))
            except (HTTPException, urllib.error.URLError, TimeoutError) as err:
                print(f"An error occurred while downloading the package/s: {str(err)}")
                return
            shutil.unpack_archive(filename, f"/tmp/baurpm/")
        if "n" not in args[0]:
            print(f"Note: pass the n argument to skip reading PKGBUILD files. eg: {sys.argv[0]} -In package_name")
            for package in package_data:
                package_name = package["PackageBase"]
                print(f"Build files for \033[1m{package_name}\033[0m are:"
                      f"\n     {' '.join(os.listdir(f'/tmp/baurpm/{package_name}'))}")
                print(f"See \033[1m/tmp/baurpm/{package_name}\033[0m for more information.")
                input("Press Enter to continue and view PKGBUILD")
                viewing_process = subprocess.Popen(
                    ["less", f"/tmp/baurpm/{package_name}/PKGBUILD"], stderr=subprocess.PIPE
                )
                viewing_failed = viewing_process.wait()
                if viewing_failed:
                    print(
                        f"\033[1;33mWarning\033[0m: Viewing package info failed with exit code {viewing_failed}: "
                        f"{viewing_process.stderr.read().decode('utf-8')}"
                    )
            raw_response = input(f"Continue Installation? [Y/n]: ")
            if not raw_response.lower().startswith("y"):
                print("aborting...")
                return
        print("Checking dependencies...")
        original_directory = os.getcwd()
        to_fetch = []
        fetched_bases = []
        for package in package_data:
            if package["Name"] != package["PackageBase"] and package["PackageBase"] not in fetched_bases:
                fetched_bases.append(package["PackageBase"])
                print(f"Fetching info on dependencies for package base \x1b[1m{package['PackageBase']}\x1b[0m...")
                os.chdir(f"/tmp/baurpm/{package['PackageBase']}")
                if os.getuid() == 0:
                    shutil.chown(os.getcwd(), os.getenv('SUDO_USER') or 'nobody')
                    makepkg_info_cmd = os.popen(f"sudo -u {os.getenv('SUDO_USER') or 'nobody'} makepkg --printsrcinfo")
                else:
                    makepkg_info_cmd = os.popen("makepkg --printsrcinfo")
                makepkg_info = makepkg_info_cmd.read().splitlines()
                makepkg_info_failed = (makepkg_info_cmd.close() or 255) >> 8
                if makepkg_info_failed:
                    print(f"\033[1;31mFatal\033[0m: Fetching info on dependencies for package base "
                          f"\x1b[1m{package['PackageBase']}\x1b[0m failed with exit code {makepkg_info_failed}!")
                    return
                for line in makepkg_info:
                    if line.startswith("pkgname = "):
                        pkg = line.split(" = ")[1]
                        if pkg not in package_names:
                            to_fetch.append(line.split(" = ")[1])
        if len(to_fetch) > 0:
            print(f"Fetching \x1b[1m{len(to_fetch)}\x1b[0m sub packages")
            try:
                extended_package_data = self.utils.find_pkg(to_fetch)
            except PackageNotFound as error:
                print(error.message)
                return
            except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                    TimeoutError) as error:
                print(f"An error occurred while getting information on the package/s: {str(error)}")
                return
            package_data.extend(extended_package_data)
        depend_list = set()
        depend_list.update(to_fetch)
        for package in package_data:
            if package.get("Depends") is not None:
                depend_list.update(package.get("Depends"))
            if package.get("MakeDepends") is not None:
                depend_list.update(package.get("MakeDepends"))
        aur_depends = []
        if len(depend_list) > 0:
            print(f"Checking \x1b[1m{len(depend_list)}\x1b[0m dependencies for aur dependencies")
            try:
                aur_depends = self.utils.find_pkg(list(depend_list), ignore_missing=True)
            except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                    TimeoutError) as error:
                print(f"An error occurred while getting information on the package/s: {str(error)}")
                return
        aur_depends_names = [aur_pkg['Name'] for aur_pkg in aur_depends]
        if len(aur_depends) > 0:
            print(f"The following aur dependencies will be installed:\n    {' '.join(aur_depends_names)}"
                  f"\nNote: more AUR dependencies may be installed if these ones have them")
            raw_response = input("Continue Installation? [Y/n]: ")
            if not raw_response.lower().startswith("y"):
                print("aborting...")
                return
            for dependency in aur_depends:
                qm_command = os.popen("pacman -Qm")
                qm_output = qm_command.read().splitlines()
                qm_failed = (qm_command.close() or 255) >> 8
                if qm_failed:
                    print(f"\033[1;31mFatal\033[0m: Fetching installed aur packages failed with exit code {qm_failed}!")
                    return
                installed = [line.split(" ") for line in qm_output]
                installed_names = []
                installed_versions = {}
                for pkg, version in installed:
                    installed_names.append(pkg)
                    installed_versions[pkg] = version
                if dependency["Name"] in installed_names:
                    qii_command = os.popen(f"pacman -Qii {dependency['Name']}")
                    qii_output = qii_command.read().splitlines()
                    qii_failed = (qii_command.close() or 255) >> 8
                    if qii_failed:
                        print(
                            f"\033[1;31mFatal\033[0m: Fetching reverse dependencies for "
                            f"\x1b[1m{dependency['Name']}\x1b[0m failed with exit code {qii_failed}!")
                        return
                    required_by_parsing = [qii_package.split(":")[-1].split() for qii_package in qii_output if
                                           qii_package.split(":")[0].strip() == "Required By"]
                    required_by = required_by_parsing[0] if len(required_by_parsing) > 0 else []
                    if installed_versions[dependency["Name"]] != dependency["Version"] and \
                            not set(required_by).issubset(package_names):
                        print(f"\033[1;31mDependency Error\033[0m: A different version of {dependency['Name']} "
                              f"is already installed! Installation was aborted to avoid breaking packages that rely on "
                              f"this version! Please upgrade all of your AUR packages and try again. "
                              f"It is also recommended to run pacman -Syu as well")
                        return
                    else:
                        continue
                if dependency["Name"] in package_names:
                    print("dependency was in package names")
                    continue
                package_data.append(dependency)
                dep_snapshot_url: str = dependency["URLPath"]
                if dependency["Name"] != dependency["PackageBase"]:
                    dep_snapshot_url = f'{pathlib.Path(dep_snapshot_url).parents[0]}/{dependency["PackageBase"]}' \
                                   f'{"".join(pathlib.Path(dep_snapshot_url).suffixes)}'
                try:
                    dep_filename = self.utils.download_pkg(dep_snapshot_url, pathlib.Path(f"/tmp/baurpm/cache"))
                    shutil.unpack_archive(dep_filename, f"/tmp/baurpm/")
                except (HTTPException, urllib.error.URLError, TimeoutError) as err:
                    print(f"An error occurred while downloading the package/s: {str(err)}")
                    return
                os.remove(dep_filename)
                if dependency.get("Depends") is not None:
                    try:
                        aur_packages = self.utils.find_pkg(dependency["Depends"], ignore_missing=True)
                    except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError,
                            urllib.error.URLError, TimeoutError) as error:
                        print(f"An error occurred while getting information on the package/s: {str(error)}")
                        return
                    aur_depends += aur_packages
        built_pkgs = []
        for idx, package in enumerate(package_data):
            package_name = package["PackageBase"]
            to_install_packages = set([to_install["PackageBase"] for to_install in package_data])
            if package_name not in built_pkgs:
                if len(to_install_packages) > 1:
                    print(f"Making Package {idx+1}/{len(to_install_packages)}: \033[1m{package_name}\033[0m")
                else:
                    print(f"Making \033[1m{package_name}\033[0m")
                os.chdir(f'/tmp/baurpm/{package_name}')
                if os.getuid() == 0:
                    shutil.chown(os.getcwd(), os.getenv('SUDO_USER') or 'nobody')
                    makepkg_process = subprocess.Popen(
                        ["sudo", "-u", os.getenv('SUDO_USER') or 'nobody', "makepkg", "-sf"], stderr=subprocess.PIPE
                    )
                else:
                    makepkg_process = subprocess.Popen(
                        ["makepkg", "-sf"], stderr=subprocess.PIPE
                    )
                makepkg_failed = makepkg_process.wait()
                if makepkg_failed:
                    print(
                        f"\033[1;31mFatal\033[0m: makepkg process failed with exit code {makepkg_failed}: "
                        f"{makepkg_process.stderr.read().decode('utf-8')}"
                    )
                    return
                built_pkgs.append(package["PackageBase"])
        os.chdir(original_directory)
        package_paths = []
        already_listed = []
        for package in package_data:
            package_name = package["PackageBase"]
            if package_name not in already_listed:
                for build_file in os.listdir(f'/tmp/baurpm/{package_name}'):
                    if build_file.endswith(".pkg.tar.zst"):
                        package_paths.append(f'/tmp/baurpm/{package_name}/{build_file}')
                        already_listed.append(package_name)
        print(f"Installing {len(package_paths)} packages...")
        if os.getuid() == 0:
            install_failed = os.system(f"pacman -U {' '.join(package_paths)}") >> 8
        else:
            install_failed = os.system(f"sudo pacman -U {' '.join(package_paths)}") >> 8
        if install_failed:
            print(f"\033[1;31mFatal\033[0m: Installing process failed with exit code {install_failed}!")
            return
        else:
            print("Cleaning up build files...")
            deletion_process = subprocess.Popen(
                ["rm", "-rf", "/tmp/baurpm"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
            deletion_failed = deletion_process.wait()
            if deletion_failed:
                print(
                    f"\033[1;31mFatal\033[0m: Deleting build files failed with exit code "
                    f"{deletion_failed}: {deletion_process.stderr.read().decode('utf-8')}"
                )
        print("Done!")

    def command_c(self, *args):
        """Check for newer versions of installed packages

        Usage:
            {name}[options] [arguments]
        Options:
            i, <packages>: Ignore upgrading packages specified
            f: Ignore any missing packages
            s: Skip running pacman -Syu
            k: Upgrade archlinux-keyring first
        """
        print("Checking for newer versions of AUR packages...")
        qm_command = os.popen("pacman -Qm")
        qm_output = qm_command.read().splitlines()
        qm_failed = (qm_command.close() or 255) >> 8
        if qm_failed:
            print(f"\033[1;31mFatal\033[0m: Fetching installed aur packages failed with exit code {qm_failed}!")
            return
        installed = [line.split(" ") for line in qm_output]
        installed_names = []
        installed_versions = {}
        for pkg, version in installed:
            if "i" in args[0] and pkg in args[1]:
                print(f"Ignoring specified package: {pkg}")
                continue
            if pkg.endswith("-debug"):
                continue
            installed_names.append(pkg)
            installed_versions[pkg] = version
        print(f"Checking {len(installed_names)} AUR packages...")
        try:
            package_data = self.utils.find_pkg(installed_names)
        except PackageNotFound as error:
            if "f" in args[0]:
                stripped_packages = [raw_pkg for raw_pkg in installed_names if raw_pkg not in error.missing_packages]
                try:
                    package_data = self.utils.find_pkg(stripped_packages)
                except PackageNotFound as error:
                    print(error.message)
                    print(f"Note: Use \x1b[1m{__title__} -Ci package-name\x1b[0m to ignore packages")
                    return
                except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError,
                        urllib.error.URLError, TimeoutError) as error:
                    print(f"An error occurred while getting information on the package/s: {str(error)}")
                    return
            else:
                print(error.message)
                print(f"Note: Use \x1b[1m{__title__} -Ci package-name\x1b[0m to ignore packages")
                return
        except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                TimeoutError) as error:
            print(f"An error occurred while getting information on the package/s: {str(error)}")
            return
        upgradable = []
        upgradable_names = []
        for package in package_data:
            if package["Version"] != installed_versions[package["Name"]]:
                upgradable.append(package)
                upgradable_names.append(package["Name"])
        if len(upgradable) > 0:
            print(f"{len(upgradable)} AUR packages can be upgraded:\n    {' '.join(upgradable_names)}")
            raw_response = input("Upgrade these packages now? [Y/n]: ")
            if not raw_response.lower().startswith("y"):
                print("aborting...")
                return
            print("It is recommended to run pacman -Syu before upgrading these packages")
            print(f"Note: pass the s argument to skip running running pacman -Syu ("
                  f"NOT RECOMMENDED unless you have already done so). "
                  f"eg: {sys.argv[0]} -Cs package_name")
            before_mod_times = self.utils.fetch_initramfs_mod_times()
            if "s" not in args[0]:
                # raw_response = input("Update archlinux-keyring first? [y/N]: ")
                print("Note: If you run into package signature errors, try upgrading the archlinux-keyring"
                      f"by passing the k argument: eg: {sys.argv[0]} -Ck package_name")
                if "k" in args[0]:
                    print("Attempting to upgrade archlinux-keyring first to prevent signature errors...")
                    if os.getuid() == 0:
                        keyring_update_failed = os.system("pacman -Sy archlinux-keyring") >> 8
                    else:
                        keyring_update_failed = os.system("sudo pacman -Sy archlinux-keyring") >> 8
                    if keyring_update_failed:
                        print("Failed to upgrade archlinux-keyring.")
                    else:
                        print("Successfully upgraded archlinux-keyring")
                    print("\x1b[1;33mWARNING\x1b[0m: The system has been \x1b[mPARTIALLY UPGRADED!\x1b[0m In other "
                          "words "
                          "aborting now and not fully upgrading with pacman -Syu may leave your system in a "
                          "broken state! So please let it run or do it manually")
                if os.getuid() == 0:
                    upgrade_failed = os.system("pacman -Syu") >> 8
                else:
                    upgrade_failed = os.system("sudo pacman -Syu") >> 8
                if upgrade_failed:
                    print(f"\033[1;31mFatal\033[0m: pacman -Syu failed with exit code {upgrade_failed}!")
                    return
            self.command_i(args[0], upgradable_names, package_data=upgradable)
            after_mod_times = self.utils.fetch_initramfs_mod_times()
            initramfs_image_updated = False
            for key, value in after_mod_times.items():
                if before_mod_times[key] != value:
                    initramfs_image_updated = True
            if initramfs_image_updated:
                print("The initramfs has been updated and you will need to reboot the system to use some new software.")
                print("Do you want to restart now?")
                print(
                    "Type \x1b[1mYes\x1b[0m to reboot. \n\x1b[1;31m"
                    "WARNING: typing Yes will reboot your computer! Any unsaved work will be lost!\x1b[0m"
                )
                raw_response = input(f" ?]: ")
                if raw_response == "Yes":
                    reboot_failed = os.system("sudo reboot") >> 8
                    if reboot_failed:
                        print("Reboot command failed, you will need to rebot manually")
                    else:
                        print("Rebooting...")
        else:
            print("\x1b[1mAll installed AUR packages are up to date\x1b[0m")

    def command_u(self, *args):
        """Upgrade packages that have been downloaded in ~/stored-aur-packages (not yet implemented)"""
        print("Checking for newer versions of AUR packages...")
        qm_command = os.popen("pacman -Qm")
        qm_output = qm_command.read().splitlines()
        qm_failed = (qm_command.close() or 255) >> 8
        if qm_failed:
            print(f"\033[1;31mFatal\033[0m: Fetching installed aur packages failed with exit code {qm_failed}!")
            return
        installed = [line.split(" ") for line in qm_output]
        installed_names = []
        installed_versions = {}
        for pkg, version in installed:
            if "i" in args[0] and pkg in args[1]:
                print(f"Ignoring specified package: {pkg}")
                continue
            if pkg.endswith("-debug"):
                continue
            installed_names.append(pkg)
            installed_versions[pkg] = version
        print(f"Checking {len(installed_names)} AUR packages...")
        try:
            package_data = self.utils.find_pkg(installed_names)
        except PackageNotFound as error:
            if "f" in args[0]:
                stripped_packages = [raw_pkg for raw_pkg in installed_names if raw_pkg not in error.missing_packages]
                try:
                    package_data = self.utils.find_pkg(stripped_packages)
                except PackageNotFound as error:
                    print(error.message)
                    print(f"Note: Use \x1b[1m{__title__} -Ci package-name\x1b[0m to ignore packages")
                    return
                except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError,
                        urllib.error.URLError, TimeoutError) as error:
                    print(f"An error occurred while getting information on the package/s: {str(error)}")
                    return
            else:
                print(error.message)
                print(f"Note: Use \x1b[1m{__title__} -Ci package-name\x1b[0m to ignore packages")
                return
        except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                TimeoutError) as error:
            print(f"An error occurred while getting information on the package/s: {str(error)}")
            return
        upgradable = []
        upgradable_names = []
        for package in package_data:
            if package["Version"] != installed_versions[package["Name"]]:
                upgradable.append(package)
                upgradable_names.append(package["Name"])
        if len(upgradable) > 0:
            print(f"{len(upgradable)} AUR packages can be upgraded:\n    {' '.join(upgradable_names)}")
            raw_response = input("Upgrade these packages now? [Y/n]: ")
            if not raw_response.lower().startswith("y"):
                print("aborting...")
                return
            print("It is recommended to run pacman -Syu before upgrading these packages")
            print(f"Note: pass the s argument to skip running running pacman -Syu ("
                  f"NOT RECOMMENDED unless you have already done so). "
                  f"eg: {sys.argv[0]} -Cs package_name")
            before_mod_times = self.utils.fetch_initramfs_mod_times()
            if "s" not in args[0]:
                # raw_response = input("Update archlinux-keyring first? [y/N]: ")
                print("Note: If you run into package signature errors, try upgrading the archlinux-keyring"
                      f"by passing the k argument: eg: {sys.argv[0]} -Ck package_name")
                if "k" in args[0]:
                    print("Attempting to upgrade archlinux-keyring first to prevent signature errors...")
                    if os.getuid() == 0:
                        keyring_update_failed = os.system("pacman -Sy archlinux-keyring") >> 8
                    else:
                        keyring_update_failed = os.system("sudo pacman -Sy archlinux-keyring") >> 8
                    if keyring_update_failed:
                        print("Failed to upgrade archlinux-keyring.")
                    else:
                        print("Successfully upgraded archlinux-keyring")
                    print("\x1b[1;33mWARNING\x1b[0m: The system has been \x1b[mPARTIALLY UPGRADED!\x1b[0m In other "
                          "words "
                          "aborting now and not fully upgrading with pacman -Syu may leave your system in a "
                          "broken state! So please let it run or do it manually")
                if os.getuid() == 0:
                    upgrade_failed = os.system("pacman -Syu") >> 8
                else:
                    upgrade_failed = os.system("sudo pacman -Syu") >> 8
                if upgrade_failed:
                    print(f"\033[1;31mFatal\033[0m: pacman -Syu failed with exit code {upgrade_failed}!")
                    return
            self.command_a(args[0], upgradable_names, package_data=upgradable)
            after_mod_times = self.utils.fetch_initramfs_mod_times()
            initramfs_image_updated = False
            for key, value in after_mod_times.items():
                if before_mod_times[key] != value:
                    initramfs_image_updated = True
            if initramfs_image_updated:
                print("The initramfs has been updated and you will need to reboot the system to use some new software.")
                print("Do you want to restart now?")
                print(
                    "Type \x1b[1mYes\x1b[0m to reboot. \n\x1b[1;31m"
                    "WARNING: typing Yes will reboot your computer! Any unsaved work will be lost!\x1b[0m"
                )
                raw_response = input(f" ?]: ")
                if raw_response == "Yes":
                    reboot_failed = os.system("sudo reboot") >> 8
                    if reboot_failed:
                        print("Reboot command failed, you will need to rebot manually")
                    else:
                        print("Rebooting...")
        else:
            print("\x1b[1mAll installed AUR packages are up to date\x1b[0m")

    def command_v(self, *args, **kwargs):
        """"""
        print("not implemented")

    def command_a(self, *args, **kwargs):
        """
        install a package by adding it to the ~/stored-aur-packages directory and installing it (not yet implemented)
        """
        if not kwargs.get("package_data"):
            print(f"Searching for \x1b[1m{', '.join(args[1])}\x1b[0m")
            try:
                package_data = self.utils.find_pkg(args[1])
            except PackageNotFound as error:
                if "f" in args[0]:
                    stripped_packages = [raw_pkg for raw_pkg in args[1] if raw_pkg not in error.missing_packages]
                    try:
                        package_data = self.utils.find_pkg(stripped_packages)
                    except PackageNotFound as error:
                        print(error.message)
                        return
                else:
                    print(error.message)
                    return
            except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                    TimeoutError) as error:
                print(f"An error occurred while getting information on the package/s: {str(error)}")
                return
            package_names = [package["Name"] for package in package_data]
            if len(package_names) < 2:
                found_message = f"A package called \033[1m{package_names[0]}\033[0m was found." \
                                f"\nMake and install the package?"
            else:
                found_message = f"Some packages called \033[1m{', '.join(package_names)}\033[0m were found." \
                                f"\nMake and install the packages?"
            raw_response = input(f"{found_message} [Y/n]: ")
            if not raw_response.lower().startswith("y"):
                print("aborting...")
                return
        else:
            package_data = kwargs["package_data"]
            package_names = [package["Name"] for package in package_data]
        bases = []
        for package in package_data:
            if package["Name"] != package["PackageBase"]:
                if package["PackageBase"] not in bases:
                    bases.append(package["PackageBase"])
                else:
                    continue
            if kwargs.get("package_data"):
                if pathlib.Path(f"~/stored-aur-packages/{package['PackageBase']}/PKGBUILD").exists():
                    try:
                        self.utils.git_pull_pkg(package["PackageBase"], pathlib.Path(f"~/stored-aur-packages"))
                    except BAURPMException as err:
                        print(f"An error occurred while downloading the package/s: {str(err)}")
                        return
                else:
                    print(f"Package {package['PackageBase']} not cloned into ~/stored-aur-packages. Cloning...")
                    try:
                        self.utils.git_clone_pkg(
                            package["PackageBase"], pathlib.Path(f"~/stored-aur-packages")
                        )
                    except BAURPMException as err:
                        print(f"An error occurred while downloading the package/s: {str(err)}")
                        return
            else:
                if not pathlib.Path(f"~/stored-aur-packages/{package['PackageBase']}/PKGBUILD").exists():
                    try:
                        self.utils.git_clone_pkg(
                            package["PackageBase"], pathlib.Path(f"~/stored-aur-packages")
                        )
                    except BAURPMException as err:
                        print(f"An error occurred while downloading the package/s: {str(err)}")
                        return
                else:
                    print("Package already cloned. Checking for updates...")
                    makepkg_info_cmd = os.popen(
                        f"makepkg --dir ~/stored-aur-packages/{package['PackageBase']} --printsrcinfo"
                    )
                    makepkg_info = makepkg_info_cmd.read().splitlines()
                    makepkg_info_failed = (makepkg_info_cmd.close() or 255) >> 8
                    if makepkg_info_failed:
                        print(f"\033[1;31mFatal\033[0m: Fetching info on dependencies for package base "
                              f"\x1b[1m{package['PackageBase']}\x1b[0m failed with exit code {makepkg_info_failed}!")
                        return
                    pkg_ver = None
                    epoch = None
                    pkg_rel = None
                    for line in makepkg_info:
                        if line.strip().startswith("pkgver = "):
                            pkg_ver = line.split(" = ")[1]
                        if line.strip().startswith("epoch = "):
                            epoch = line.split(" = ")[1]
                        if line.strip().startswith("pkgrel = "):
                            pkg_rel = line.split(" = ")[1]
                    full_package_str = (
                            (f"{epoch}:" if epoch else "") + (pkg_ver or "") + (f"-{pkg_rel}" if pkg_rel else "")
                    )
                    if pkg_ver and full_package_str != package["Version"]:
                        print("Update Available")
                        raw_response = input(f"Git Pull to update? [Y/n]: ")
                        if raw_response.lower().startswith("y"):
                            try:
                                self.utils.git_pull_pkg(package["PackageBase"], pathlib.Path(f"~/stored-aur-packages"))
                            except BAURPMException as err:
                                print(f"An error occurred while downloading the package/s: {str(err)}")
                                return
                    else:
                        print(f"\033[1;33mWarning\033[0m: {package['Name']} is already up to date -- reinstalling")
        if "n" not in args[0]:
            print(f"Note: pass the n argument to skip reading PKGBUILD files. eg: {sys.argv[0]} -An package_name")
            for package in package_data:
                package_name = package["PackageBase"]
                print(f"Build files for \033[1m{package_name}\033[0m are:"
                      f"\n     {' '.join(os.listdir(os.path.expanduser(f'~/stored-aur-packages/{package_name}')))}")
                print(f"See \033[1m~/stored-aur-packages/{package_name}\033[0m for more information.")
                input("Press Enter to continue and view PKGBUILD")
                viewing_process = subprocess.Popen(
                    ["less", str(pathlib.Path(f"~/stored-aur-packages/{package_name}/PKGBUILD").expanduser())],
                    stderr=subprocess.PIPE
                )
                viewing_failed = viewing_process.wait()
                if viewing_failed:
                    print(
                        f"\033[1;33mWarning\033[0m: Viewing package info failed with exit code {viewing_failed}: "
                        f"{viewing_process.stderr.read().decode('utf-8')}"
                    )
            raw_response = input(f"Continue Installation? [Y/n]: ")
            if not raw_response.lower().startswith("y"):
                print("aborting...")
                return
        print("Checking dependencies...")
        original_directory = os.getcwd()
        to_fetch = []
        fetched_bases = []
        for package in package_data:
            if package["Name"] != package["PackageBase"] and package["PackageBase"] not in fetched_bases:
                fetched_bases.append(package["PackageBase"])
                print(f"Fetching info on dependencies for package base \x1b[1m{package['PackageBase']}\x1b[0m...")
                os.chdir(os.path.expanduser(f"~/stored-aur-packages/{package['PackageBase']}"))
                if os.getuid() == 0:
                    shutil.chown(os.getcwd(), os.getenv('SUDO_USER') or 'nobody')
                    makepkg_info_cmd = os.popen(f"sudo -u {os.getenv('SUDO_USER') or 'nobody'} makepkg --printsrcinfo")
                else:
                    makepkg_info_cmd = os.popen("makepkg --printsrcinfo")
                makepkg_info = makepkg_info_cmd.read().splitlines()
                makepkg_info_failed = (makepkg_info_cmd.close() or 255) >> 8
                if makepkg_info_failed:
                    print(f"\033[1;31mFatal\033[0m: Fetching info on dependencies for package base "
                          f"\x1b[1m{package['PackageBase']}\x1b[0m failed with exit code {makepkg_info_failed}!")
                    return
                for line in makepkg_info:
                    if line.startswith("pkgname = "):
                        pkg = line.split(" = ")[1]
                        if pkg not in package_names:
                            to_fetch.append(line.split(" = ")[1])
        if len(to_fetch) > 0:
            print(f"Fetching \x1b[1m{len(to_fetch)}\x1b[0m sub packages")
            try:
                extended_package_data = self.utils.find_pkg(to_fetch)
            except PackageNotFound as error:
                print(error.message)
                return
            except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                    TimeoutError) as error:
                print(f"An error occurred while getting information on the package/s: {str(error)}")
                return
            package_data.extend(extended_package_data)
        depend_list = set()
        depend_list.update(to_fetch)
        for package in package_data:
            if package.get("Depends") is not None:
                depend_list.update(package.get("Depends"))
            if package.get("MakeDepends") is not None:
                depend_list.update(package.get("MakeDepends"))
        aur_depends = []
        if len(depend_list) > 0:
            print(f"Checking \x1b[1m{len(depend_list)}\x1b[0m dependencies for aur dependencies")
            try:
                aur_depends = self.utils.find_pkg(list(depend_list), ignore_missing=True)
            except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError, urllib.error.URLError,
                    TimeoutError) as error:
                print(f"An error occurred while getting information on the package/s: {str(error)}")
                return
        aur_depends_names = [aur_pkg['Name'] for aur_pkg in aur_depends]
        if len(aur_depends) > 0:
            print(f"The following aur dependencies will be installed:\n    {' '.join(aur_depends_names)}"
                  f"\nNote: more AUR dependencies may be installed if these ones have them")
            raw_response = input("Continue Installation? [Y/n]: ")
            if not raw_response.lower().startswith("y"):
                print("aborting...")
                return
            for dependency in aur_depends:
                qm_command = os.popen("pacman -Qm")
                qm_output = qm_command.read().splitlines()
                qm_failed = (qm_command.close() or 255) >> 8
                if qm_failed:
                    print(f"\033[1;31mFatal\033[0m: Fetching installed aur packages failed with exit code {qm_failed}!")
                    return
                installed = [line.split(" ") for line in qm_output]
                installed_names = []
                installed_versions = {}
                for pkg, version in installed:
                    installed_names.append(pkg)
                    installed_versions[pkg] = version
                if dependency["Name"] in installed_names:
                    qii_command = os.popen(f"pacman -Qii {dependency['Name']}")
                    qii_output = qii_command.read().splitlines()
                    qii_failed = (qii_command.close() or 255) >> 8
                    if qii_failed:
                        print(
                            f"\033[1;31mFatal\033[0m: Fetching reverse dependencies for "
                            f"\x1b[1m{dependency['Name']}\x1b[0m failed with exit code {qii_failed}!")
                        return
                    required_by_parsing = [qii_package.split(":")[-1].split() for qii_package in qii_output if
                                           qii_package.split(":")[0].strip() == "Required By"]
                    required_by = required_by_parsing[0] if len(required_by_parsing) > 0 else []
                    if installed_versions[dependency["Name"]] != dependency["Version"] and \
                            not set(required_by).issubset(package_names):
                        print(f"\033[1;31mDependency Error\033[0m: A different version of {dependency['Name']} "
                              f"is already installed! Installation was aborted to avoid breaking packages that rely on "
                              f"this version! Please upgrade all of your AUR packages and try again. "
                              f"It is also recommended to run pacman -Syu as well")
                        return
                    else:
                        continue
                if dependency["Name"] in package_names:
                    print("dependency was in package names")
                    continue
                package_data.append(dependency)
                try:
                    self.utils.git_clone_pkg(dependency["PackageBase"], pathlib.Path(f"~/stored-aur-packages"))
                except BAURPMException as err:
                    print(f"An error occurred while downloading the package/s: {str(err)}")
                    return
                if dependency.get("Depends") is not None:
                    try:
                        aur_packages = self.utils.find_pkg(dependency["Depends"], ignore_missing=True)
                    except (AURWebRTCError, HTTPException, UnexpectedContentType, json.JSONDecodeError,
                            urllib.error.URLError, TimeoutError) as error:
                        print(f"An error occurred while getting information on the package/s: {str(error)}")
                        return
                    aur_depends += aur_packages
        built_pkgs = []
        for idx, package in enumerate(package_data):
            package_name = package["PackageBase"]
            to_install_packages = set([to_install["PackageBase"] for to_install in package_data])
            if package_name not in built_pkgs:
                if len(to_install_packages) > 1:
                    print(f"Making Package {idx + 1}/{len(to_install_packages)}: \033[1m{package_name}\033[0m")
                else:
                    print(f"Making \033[1m{package_name}\033[0m")
                os.chdir(os.path.expanduser(f'~/stored-aur-packages/{package_name}'))
                if os.getuid() == 0:
                    shutil.chown(os.getcwd(), os.getenv('SUDO_USER') or 'nobody')
                    makepkg_process = subprocess.Popen(
                        ["sudo", "-u", os.getenv('SUDO_USER') or 'nobody', "makepkg", "-sf"], stderr=subprocess.PIPE
                    )
                else:
                    makepkg_process = subprocess.Popen(
                        ["makepkg", "-sf"], stderr=subprocess.PIPE
                    )
                makepkg_failed = makepkg_process.wait()
                if makepkg_failed:
                    print(
                        f"\033[1;31mFatal\033[0m: makepkg process failed with exit code {makepkg_failed}: "
                        f"{makepkg_process.stderr.read().decode('utf-8')}"
                    )
                    return
                built_pkgs.append(package["PackageBase"])
        os.chdir(original_directory)
        package_paths = []
        already_listed = []
        for package in package_data:
            package_name = package["PackageBase"]
            if package_name not in already_listed:
                for build_file in os.listdir(os.path.expanduser(f'~/stored-aur-packages/{package_name}')):
                    if build_file.endswith(".pkg.tar.zst"):
                        package_paths.append(f'~/stored-aur-packages/{package_name}/{build_file}')
                        already_listed.append(package_name)
        print(f"Installing {len(package_paths)} packages...")
        if os.getuid() == 0:
            install_failed = os.system(f"pacman -U {' '.join(package_paths)}") >> 8
        else:
            install_failed = os.system(f"sudo pacman -U {' '.join(package_paths)}") >> 8
        if install_failed:
            print(f"\033[1;31mFatal\033[0m: Installing process failed with exit code {install_failed}!")
            return
        else:
            pass
        print("Done!")


baurpm_commands = BAURPMCommands()


if __name__ == "__main__":
    print(f"{LONG_NAME} {__version__}\n{__copyright__}")

    if len(sys.argv) < 2:
        print(f"No commands provided!\nUsage: {__title__} [command][options] [arguments]\nSee {__title__} help for "
              f"details")
        exit(1)

    command_arg = sys.argv[1]
    if not command_arg.startswith("-") and command_arg.startswith("help"):
        command_arg = "-H"
    if len(sys.argv) > 2:
        command_args = sys.argv[2:]
    else:
        command_args = []

    if command_arg.startswith("-") and len(command_arg) > 1:
        cmd_name = command_arg[1] if not command_arg.startswith("--") else command_arg[2]
        cmd_opts = list(command_arg[2:])
        func_name = f"command_{cmd_name.lower()}"
        if hasattr(baurpm_commands, func_name):
            try:
                to_run = getattr(baurpm_commands, func_name)
                to_run(cmd_opts, command_args)
            except KeyboardInterrupt:
                print("Exiting...")
                exit(130)
            except HTTPException as e:
                print(f"An error occurred while making a request to the server: {str(e)}")
                exit(1)
            except urllib.error.URLError as e:
                print(f"An error occurred while connecting to the server: {str(e)}")
                exit(1)
            except Exception:
                raise
        else:
            print(f'{__title__}: command "{cmd_name}" not found')
