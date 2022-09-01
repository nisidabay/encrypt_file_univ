#!/usr/bin/python3

##############################################################################
# Author: Carlos Lacaci Moya
# Description: Helper Clases and functions for the script
# Date: dom 24 jul 2022 18:28:11 CEST
# version : 1.0.0
##############################################################################

import os
import sys
import socket
from pathlib import Path as path
from rich import print as pr
from rich.panel import Panel
from rich.console import Console
from rich.rule import Rule
from rich.progress import Progress
from PIL import Image  # type: ignore
"""Bunch of helpful utilities accross different projects"""


def abspath(file: str, dir: str = ".") -> str:
    """Returns the absolute path of a resource. 
       Default dir current working directory"""

    file_path = path(__file__).parent.absolute().joinpath(dir).joinpath(file)
    if file_path.exists():
        return str(file_path)
    else:
        return ""


def dirpath(dir: str) -> str:
    """Returns the absolute path of a directory"""

    dirpath = ""
    if path(dir).exists():
        p = path(dir)
        dirpath = str(p.resolve())
    else:
        pr(f"Folder: [bold red]<{dir}> does not exist![/bold red] :bomb: :boom:"
           )

    return dirpath


def clear_screen() -> None:
    """Clear the screen"""

    os.system("clear")


def is_host_oneline(ip_address: str, verbose: bool = False) -> bool:
    """Check if a host in online"""

    status = False
    try:
        host, _, ip = socket.gethostbyaddr(ip_address)
        if verbose:
            pr(f"Found host: [green]{host} [/green] with ip: [yellow]{ip}[/yellow] :thumbsup:"
               )
        status = True

    except socket.herror:
        pr(f"Unknown host: [bold red]{ip_address}[/bold red]")
        pr("[bold red]Are you online???[/bold red] :bomb: :boom:")
        sys.exit(1)
    return status


def show_image(name: str):
    """Show an image store in pictures folder"""

    # read the image
    image = abspath(f"{name}.jpg")
    im = Image.open(image)

    # show image
    im.show()


class BeautiPanel(Panel):
    """Write a message inside a panel. Inherit from rich.panel"""

    @staticmethod
    def draw_panel(fontcolor: str,
                   message: str,
                   borderstyle: str = "red") -> None:
        panel = Panel.fit(f"[bold {fontcolor}]{message}",
                          border_style=f"{borderstyle}")
        pr(panel)


class HeaderLine():
    """Write an underline title message"""

    @staticmethod
    def draw_line(message: str) -> None:
        console = Console()
        console.rule(f"[bold green underline]{message}")


class Rule_(Rule):
    """Writes an underline title message. Inherits from rich.rule"""

    @staticmethod
    def draw_rule(message: str) -> None:
        console = Console()
        console.rule(f"[blink bold white on black]{message}")


def progress_bar():
    """Fake progress bar"""
    with Progress() as progress:
        task = progress.add_task("[green]Syncing ...", total=10000)

        while not progress.finished:
            progress.update(task, advance=0.01)
