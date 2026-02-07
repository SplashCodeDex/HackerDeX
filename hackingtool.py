#!/usr/bin/env python3
# Version 1.1.0 (rich UI - purple theme)
import os
import sys

# Add web_ui to path for intelligence modules
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web_ui'))

from platform import system
from time import sleep
from typing import List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.align import Align
from rich.text import Text
from rich import box
from rich.rule import Rule

from core import HackingToolsCollection
from hackingtool_definitions import TOOL_DEFINITIONS, ALL_TOOLS

console = Console()

ASCII_LOGO = r"""
   ▄█    █▄       ▄████████  ▄████████    ▄█   ▄█▄  ▄█  ███▄▄▄▄      ▄██████▄           ███      ▄██████▄   ▄██████▄   ▄█
  ███    ███     ███    ███ ███    ███   ███ ▄███▀ ███  ███▀▀▀██▄   ███    ███      ▀█████████▄ ███    ███ ███    ███ ███
  ███    ███     ███    ███ ███    █▀    ███▐██▀   ███▌ ███   ███   ███    █▀          ▀███▀▀██ ███    ███ ███    ███ ███
 ▄███▄▄▄▄███▄▄   ███    ███ ███         ▄█████▀    ███▌ ███   ███  ▄███                 ███   ▀ ███    ███ ███    ███ ███
▀▀███▀▀▀▀███▀  ▀███████████ ███        ▀▀█████▄    ███▌ ███   ███ ▀▀███ ████▄           ███     ███    ███ ███    ███ ███
  ███    ███     ███    ███ ███    █▄    ███▐██▄   ███  ███   ███   ███    ███          ███     ███    ███ ███    ███ ███
  ███    ███     ███    ███ ███    ███   ███ ▀███▄ ███  ███   ███   ███    ███          ███     ███    ███ ███    ███ ███▌    ▄
  ███    █▀      ███    █▀  ████████▀    ███   ▀█▀ █▀    ▀█   █▀    ████████▀          ▄████▀    ▀██████▀   ▀██████▀  █████▄▄██
                                         ▀                                                                            ▀
"""

# Alias for backward compatibility
all_tools = ALL_TOOLS

class AllTools(HackingToolsCollection):
    TITLE = "All tools"
    TOOLS = ALL_TOOLS

    def show_info(self):
        header = Text()
        header.append(ASCII_LOGO, style="bold magenta")
        header.append("\n\n",)
        footer = Text.assemble(
            (" https://github.com/Z4nzu/hackingtool ", "bold bright_black"),
            (" | ",),
            ("Version 1.1.0", "bold green"),
        )
        warning = Text(" Please Don't Use For illegal Activity ", style="bold red")
        panel = Panel(
            Align.center(header + Text("\n") + footer + Text("\n") + warning),
            box=box.DOUBLE,
            padding=(1, 2),
            border_style="magenta"
        )
        console.print(panel)


def build_menu():
    table = Table.grid(expand=True)
    table.add_column("idx", width=6, justify="right")
    table.add_column("name", justify="left")

    for idx, (title, icon) in enumerate(TOOL_DEFINITIONS):
        if idx == 18:
            label = "[bold magenta]99[/bold magenta]"
            name = f"[bold magenta]{icon} {title}[/bold magenta]"
        else:
            label = f"[bold magenta]{idx}[/bold magenta]"
            name = f"[white]{icon}[/white]  [magenta]{title}[/magenta]"
        table.add_row(label, name)

    top_panel = Panel(
        Align.center(Text("HackingTool — Main Menu", style="bold white on magenta"), vertical="middle"),
        style="magenta",
        padding=(0, 1),
        box=box.ROUNDED
    )
    menu_panel = Panel.fit(
        table,
        title="[bold magenta]Select a tool[/bold magenta]",
        border_style="bright_magenta",
        box=box.SQUARE
    )
    footer = Align.center(Text("Choose number and press Enter — 99 to exit", style="italic bright_black"))
    console.print(top_panel)
    console.print(menu_panel)
    console.print(Rule(style="bright_black"))
    console.print(footer)
    console.print("")


def choose_path():
    """
    Sets up the installation path for tools.
    """
    fpath = os.path.expanduser("~/hackingtoolpath.txt")
    if not os.path.exists(fpath):
        console.clear()
        build_menu()
        console.print(Panel("Setup path for tool installations", border_style="magenta"))
        choice = Prompt.ask("[magenta]Set Path[/magenta]", choices=["1", "2"], default="2")
        if choice == "1":
            inpath = Prompt.ask("[magenta]Enter Path (with Directory Name)[/magenta]")
            with open(fpath, "w") as f:
                f.write(inpath)
            console.print(f"[green]Successfully Set Path to:[/green] {inpath}")
        else:
            autopath = "/home/hackingtool/"
            with open(fpath, "w") as f:
                f.write(autopath)
            console.print(f"[green]Your Default Path Is:[/green] {autopath}")
            sleep(1)
    return fpath


def interact_menu():
    while True:
        try:
            build_menu()
            choice = IntPrompt.ask("[magenta]Choose a tool to proceed[/magenta]", default=0)
            if choice == 99:
                console.print(Panel("[bold white on magenta]Goodbye — Come Back Safely[/bold white on magenta]"))
                break
            if 0 <= choice < len(ALL_TOOLS):
                tool = ALL_TOOLS[choice]
                name = TOOL_DEFINITIONS[choice][0]
                console.print(Panel(f"[bold magenta]{TOOL_DEFINITIONS[choice][1]}  Selected:[/bold magenta] [white]{name}"))
                try:
                    # Check for show_options method
                    fn = getattr(tool, "show_options", None)
                    if callable(fn):
                        fn()
                    else:
                        console.print(f"[yellow]Tool '{name}' has no interactive menu (show_options).[/yellow]")
                except Exception as e:
                    console.print(Panel(f"[red]Error while opening {name}[/red]\n{e}", border_style="red"))
                
                if not Confirm.ask("[magenta]Return to main menu?[/magenta]", default=True):
                    console.print(Panel("[bold white on magenta]Exiting...[/bold white on magenta]"))
                    break
            else:
                console.print("[red]Invalid selection. Pick a number from the menu.[/red]")
        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted by user — exiting[/bold red]")
            break

def main():
    try:
        # Patch: Bypass Linux check for educational exploration on Windows
        base_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(base_dir)
        
        # Optional: Initialize path if needed (currently inactive in original code, but function exists)
        # choose_path() 
        
        AllTools().show_info()
        interact_menu()
    except KeyboardInterrupt:
        console.print("\n[bold red]Exiting ..!!![/bold red]")
        sleep(1)


if __name__ == "__main__":
    main()