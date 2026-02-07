from core import HackingTool, HackingToolsCollection, clear_screen
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from web_ui.vuln_store import VulnStore
from web_ui.attack_pather import AttackPather
from web_ui.next_best_action import NextBestActionEngine
from managers import get_gemini_client

console = Console()
PURPLE_STYLE = "bold magenta"

class ViewPrioritizedTargets(HackingTool):
    TITLE = "View Prioritized Targets"
    DESCRIPTION = "Displays all known targets sorted by risk score and priority."

    def __init__(self):
        super(ViewPrioritizedTargets, self).__init__(installable=False)
        self.store = VulnStore()

    def run(self):
        clear_screen()
        targets = self.store.get_all_targets_summary()
        
        table = Table(title="Prioritized Targets", show_lines=True, expand=True)
        table.add_column("Priority", justify="center")
        table.add_column("Target")
        table.add_column("Risk Score", justify="right")
        table.add_column("Vulns", justify="right")
        table.add_column("Ports", justify="right")

        for t in targets:
            color = "red" if t['priority_level'] == "critical" else "yellow" if t['priority_level'] == "high" else "blue"
            table.add_row(
                f"[{color}]{t['priority_level'].upper()}[/]",
                t['target'],
                f"{t['risk_score']:.2f}",
                str(t['vulns_count']),
                str(t['ports_count'])
            )
        
        console.print(table)
        Prompt.ask("
Press Enter to return")

class ViewPrioritizedVulns(HackingTool):
    TITLE = "View Prioritized Vulnerabilities"
    DESCRIPTION = "Displays a global list of vulnerabilities prioritized by potential advantage."

    def __init__(self):
        super(ViewPrioritizedVulns, self).__init__(installable=False)
        self.store = VulnStore()

    def run(self):
        clear_screen()
        vulns = self.store.get_prioritized_vulnerabilities()
        
        table = Table(title="Global Prioritized Vulnerabilities", show_lines=True, expand=True)
        table.add_column("Score", justify="right")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Target")
        table.add_column("Tool")

        for v in vulns[:20]: # Show top 20
            color = "red" if v['severity'].lower() in ['critical', 'high'] else "yellow"
            table.add_row(
                f"{v.get('score', 0):.2f}",
                f"[{color}]{v['severity'].upper()}[/]",
                v['title'],
                v['main_target'],
                v['source_tool']
            )
        
        console.print(table)
        Prompt.ask("
Press Enter to return")

class AIAttackPathAnalysis(HackingTool):
    TITLE = "AI Attack Path Analysis"
    DESCRIPTION = "Uses Gemini to analyze correlated findings and predict attack chains."

    def __init__(self):
        super(AIAttackPathAnalysis, self).__init__(installable=False)
        self.store = VulnStore()
        self.client = get_gemini_client()
        if self.client:
            self.pather = AttackPather(self.client, self.store)
        else:
            self.pather = None

    def run(self):
        clear_screen()
        if not self.pather:
            console.print("[red]Error: Gemini API client not initialized. Check GEMINI_API_KEY.[/red]")
            Prompt.ask("
Press Enter to return")
            return

        with console.status("[bold green]Analyzing attack surface with Gemini..."):
            analysis = self.pather.analyze_attack_paths()
        
        console.print(Panel(analysis, title="AI Strategic Attack Path Analysis", border_style="magenta"))
        Prompt.ask("
Press Enter to return")

class AINextBestAction(HackingTool):
    TITLE = "AI Next Best Action Suggestion"
    DESCRIPTION = "Get an autonomous recommendation on which tool to run next for a target."

    def __init__(self):
        super(AINextBestAction, self).__init__(installable=False)
        self.store = VulnStore()
        self.client = get_gemini_client()
        if self.client:
            self.engine = NextBestActionEngine(self.client, self.store)
        else:
            self.engine = None

    def run(self):
        clear_screen()
        if not self.engine:
            console.print("[red]Error: Gemini API client not initialized.[/red]")
            Prompt.ask("
Press Enter to return")
            return

        target = Prompt.ask("Enter Target (Domain/IP)")
        if not target: return

        with console.status(f"[bold green]Consulting Gemini for next steps on {target}..."):
            suggestion = self.engine.suggest_next_action(target)
        
        if suggestion.get("tool") == "error":
            console.print(f"[red]Error: {suggestion.get('reason')}[/red]")
        else:
            console.print(Panel(
                f"[bold cyan]Suggested Tool:[/bold cyan] {suggestion['tool']}
"
                f"[bold cyan]Reason:[/bold cyan] {suggestion['reason']}
"
                f"[bold yellow]Recommended Command:[/bold yellow]
{suggestion['command']}",
                title=f"AI Next Action: {target}",
                border_style="green"
            ))
        
        Prompt.ask("
Press Enter to return")

class IntelligenceEngineTools(HackingToolsCollection):
    TITLE = "Robust Intelligence Engine"
    DESCRIPTION = "Advanced analysis, prioritization, and AI-driven security strategy."
    TOOLS = [
        ViewPrioritizedTargets(),
        ViewPrioritizedVulns(),
        AIAttackPathAnalysis(),
        AINextBestAction()
    ]

    def show_options(self, parent=None):
        clear_screen()
        console.print(Panel.fit(
            f"[{PURPLE_STYLE}]Robust Intelligence Engine — Tactical Dashboard[/{PURPLE_STYLE}]
"
            "Leverage cross-tool correlation and AI to prioritize your attack surface.",
            border_style="magenta"
        ))

        table = Table(show_lines=True, expand=True)
        table.add_column("Index", justify="center", style="bold yellow")
        table.add_column("Action", justify="left", style="bold green")
        table.add_column("Description", justify="left", style="white")

        for i, tool in enumerate(self.TOOLS):
            table.add_row(str(i + 1), tool.TITLE, tool.DESCRIPTION)

        table.add_row("[red]99[/red]", "[bold red]Back[/bold red]", "Return to main menu")
        console.print(table)

        choice = Prompt.ask("Select an option", default="99")
        if choice == "99":
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(self.TOOLS):
                self.TOOLS[idx].run()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sleep(2)
        
        return self.show_options(parent=parent)
