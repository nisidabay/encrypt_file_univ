#!/usr/bin/env python3

##############################################################################
# Author: nisidabay
# Description: Wrapper class for Panel
# Modified Date: sáb 10 sep 2022 08:38:43 CEST
# Modifief Date:Thu Nov 13 11:38:17 AM CET 2025
# version : 1.2
##############################################################################

from rich import print as pr
from rich.panel import Panel


class BeautiPanel(Panel):
    """Write a message inside a panel. Inherits from rich.panel"""

    @staticmethod
    def draw_panel(fontcolor: str, message: str, borderstyle: str = "red") -> None:
        panel = Panel.fit(f"[bold {fontcolor}]{message}", border_style=f"{borderstyle}")
        pr(panel)
