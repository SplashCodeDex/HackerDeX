from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.traceback import install
from rich.theme import Theme
from rich.prompt import Prompt, IntPrompt, Confirm

import os
import sys
import webbrowser
import subprocess
from platform import system
from typing import Callable, List, Tuple, Union, Optional

# Enable rich tracebacks
install()
_theme = Theme({"purple": "#7B61FF"})
console = Console(theme=_theme)


def clear_screen():
    os.system("cls" if system() == "Windows" else "clear")


def validate_input(ip, val_range):
    val_range = val_range or []
    try:
        ip = int(ip)
        if ip in val_range:
            return ip
    except Exception:
        return None
    return None


class HackingTool(object):
    TITLE: str = ""
    DESCRIPTION: str = ""
    INSTALL_COMMANDS: List[str] = []
    INSTALLATION_DIR: str = ""
    UNINSTALL_COMMANDS: List[str] = []
    RUN_COMMANDS: List[str] = []
    OPTIONS: List[Tuple[str, Callable]] = []
    PROJECT_URL: str = ""

    def __init__(self, options: Optional[List[Tuple[str, Callable]]] = None, installable: bool = True, runnable: bool = True):
        self.executor = ToolExecutor()
        options = options or []
        if isinstance(options, list):
            self.OPTIONS = []
            if installable:
                self.OPTIONS.append(("Install", self.install))
            if runnable:
                self.OPTIONS.append(("Run", self.run))
            self.OPTIONS.extend(options)
        else:
            raise Exception("options must be a list of (option_name, option_fn) tuples")

    def show_info(self):
        desc = f"[cyan]{self.DESCRIPTION}[/cyan]"
        if self.PROJECT_URL:
            desc += f"\n[green]🔗 {self.PROJECT_URL}[/green]"
        console.print(Panel(desc, title=f"[bold purple]{self.TITLE}[/bold purple]", border_style="purple", box=box.DOUBLE))

    def show_options(self, parent=None):
        clear_screen()
        self.show_info()

        table = Table(title="Options", box=box.SIMPLE_HEAVY)
        table.add_column("No.", style="bold cyan", justify="center")
        table.add_column("Action", style="bold yellow")

        for index, option in enumerate(self.OPTIONS):
            table.add_row(str(index + 1), option[0])

        if self.PROJECT_URL:
            table.add_row("98", "Open Project Page")
        table.add_row("99", f"Back to {parent.TITLE if parent else 'Exit'}")

        console.print(table)

        try:
            option_index = IntPrompt.ask("\n[?] Select an option", default=99)
            
            if 1 <= option_index <= len(self.OPTIONS):
                ret_code = self.OPTIONS[option_index - 1][1]()
                if ret_code != 99:
                    Prompt.ask("\nPress [bold green]Enter[/bold green] to continue")
            elif option_index == 98:
                self.show_project_page()
            elif option_index == 99:
                if parent is None:
                    sys.exit()
                return 99
            else:
                console.print("[red]⚠ Please enter a valid option.[/red]")
                Prompt.ask("\nPress [bold green]Enter[/bold green] to continue")
        except Exception:
            console.print_exception(show_locals=True)
            Prompt.ask("\nPress [bold green]Enter[/bold green] to continue")
        return self.show_options(parent=parent)

    def before_install(self): pass

    def install(self):
        self.before_install()
        if isinstance(self.INSTALL_COMMANDS, (list, tuple)):
            for command in self.INSTALL_COMMANDS:
                console.print(f"[yellow]→ {command}[/yellow]")
                result = self.executor.run_blocking(command)
                if result['returncode'] != 0:
                    console.print(f"[bold red]✘ Command failed: {command}[/bold red]")
                    console.print(f"[red]Exit Code: {result['returncode']}[/red]")
                    if result['stderr']:
                        console.print(f"[red]Error: {result['stderr']}[/red]")
                    return
            self.after_install()

    def after_install(self):
        console.print("[green]✔ Successfully installed![/green]")

    def before_uninstall(self) -> bool:
        return True

    def uninstall(self):
        if self.before_uninstall():
            if isinstance(self.UNINSTALL_COMMANDS, (list, tuple)):
                for command in self.UNINSTALL_COMMANDS:
                    console.print(f"[red]→ {command}[/red]")
                    result = self.executor.run_blocking(command)
                    if result['returncode'] != 0:
                        console.print(f"[bold red]✘ Command failed: {command}[/bold red]")
                        console.print(f"[red]Exit Code: {result['returncode']}[/red]")
                        return
            self.after_uninstall()

    def after_uninstall(self): pass

    def before_run(self): pass

    def run(self):
        self.before_run()
        if isinstance(self.RUN_COMMANDS, (list, tuple)):
            for command in self.RUN_COMMANDS:
                console.print(f"[cyan]⚙ Running:[/cyan] [bold]{command}[/bold]")
                self.executor.run_blocking(command)
            self.after_run()

    def after_run(self): pass

    def is_installed(self, dir_to_check=None):
        console.print("[yellow]⚠ Unimplemented: DO NOT USE[/yellow]")
        return "?"

    def show_project_page(self):
        console.print(f"[blue]🌐 Opening project page: {self.PROJECT_URL}[/blue]")
        webbrowser.open_new_tab(self.PROJECT_URL)


class ToolExecutor:
    """
    Standardized tool execution engine for HackerDeX.
    Supports both blocking and asynchronous (streaming) execution.
    """

    def run_blocking(self, command: str) -> dict:
        """
        Executes a command and waits for it to complete.
        Returns a dictionary with stdout, stderr, and returncode.
        """
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        return {
            "stdout": stdout,
            "stderr": stderr,
            "returncode": process.returncode
        }

    def run_async(self, command: str):
        """
        Executes a command and yields output lines in real-time.
        Useful for live streaming to UI.
        """
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in iter(process.stdout.readline, ''):
            if line:
                yield line

        process.wait()


class HackingToolsCollection(object):
    TITLE: str = ""
    DESCRIPTION: str = ""
    TOOLS: List[HackingTool] = []

    def __init__(self):
        pass

    def show_info(self):
        console.rule(f"[bold purple]{self.TITLE}[/bold purple]", style="purple")
        console.print(f"[italic cyan]{self.DESCRIPTION}[/italic cyan]\n")

    def show_options(self, parent=None):
        clear_screen()
        self.show_info()

        table = Table(title="Available Tools", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("No.", justify="center", style="bold cyan")
        table.add_column("Tool Name", style="bold yellow")

        for index, tool in enumerate(self.TOOLS):
            table.add_row(str(index), tool.TITLE)

        table.add_row("99", f"Back to {parent.TITLE if parent else 'Exit'}")
        console.print(table)

        try:
            tool_index = IntPrompt.ask("\n[?] Choose a tool", default=99)

            if 0 <= tool_index < len(self.TOOLS):
                ret_code = self.TOOLS[tool_index].show_options(parent=self)
                if ret_code != 99:
                    Prompt.ask("\nPress [bold green]Enter[/bold green] to continue")
            elif tool_index == 99:
                if parent is None:
                    sys.exit()
                return 99
            else:
                console.print("[red]⚠ Please enter a valid option.[/red]")
                Prompt.ask("\nPress [bold green]Enter[/bold green] to continue")
        except Exception:
            console.print_exception(show_locals=True)
            Prompt.ask("\nPress [bold green]Enter[/bold green] to continue")
        return self.show_options(parent=parent)