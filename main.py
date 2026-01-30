import typer
import re
import os
import sys

# --- CRITICAL: FORCE UTF-8 BEFORE IMPORTING ANYTHING ELSE ---
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding='utf-8')
if os.name == 'nt':
    os.system('chcp 65001 >nul')

import time
import random
import datetime
import webbrowser
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.tree import Tree
from rich.layout import Layout
from rich.align import Align
from rich.prompt import Prompt, IntPrompt
from rich.syntax import Syntax
from rich import print as rprint
from rich.live import Live

# --- FIX: SMART ICON DETECTION SYSTEM ---
# This detects if the terminal supports emojis. If not (standard .exe), it uses safe text.
def is_modern_terminal():
    # Check for Windows Terminal, VS Code, or PyCharm environments
    if "WT_SESSION" in os.environ: return True
    if os.environ.get("TERM_PROGRAM") in ["vscode", "Apple_Terminal"]: return True
    if "PYCHARM_HOSTED" in os.environ: return True
    return False

# Setup Console based on environment
if is_modern_terminal():
    console = Console(force_terminal=True)
    # Modern Emojis
    ICON_SPIDER = "🕷️"
    ICON_SCOPE = "🔬"
    ICON_MAP = "🗺️"
    ICON_FIX = "🔧"
    ICON_CHART = "📊"
    ICON_WHALE = "🐳"
    ICON_OCTOPUS = "🐙"
    ICON_PACKAGE = "📦"
    ICON_SHIELD = "🛡️"
    ICON_CHECK = "✔"
    ICON_CROSS = "❌"
else:
    # Legacy Safe Mode (Fixes the "Square Box" issue in .exe)
    console = Console(force_terminal=True, legacy_windows=True)
    ICON_SPIDER = "[SCAN]"
    ICON_SCOPE = "[ANALYZE]"
    ICON_MAP = "[MAP]"
    ICON_FIX = "[FIX]"
    ICON_CHART = "[REPORT]"
    ICON_WHALE = "[DOCKER]"
    ICON_OCTOPUS = "[COMPOSE]"
    ICON_PACKAGE = "[SVC]"
    ICON_SHIELD = "[SECURITY]"
    ICON_CHECK = "[OK]"
    ICON_CROSS = "[ERROR]"

app = typer.Typer()

BANNER = """
[bold cyan]
██████╗  ██████╗  ██████╗██╗  ██╗███████╗██████╗ 
██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║  ██║██║   ██║██║     █████╔╝ █████╗  ██████╔╝
██║  ██║██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║
╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
[/bold cyan][bold white]       THE ARCHITECT'S CONSOLE v3.2 (FIXED EDITION)
       "Because Security is not a Feature, it's a State."
[/bold white]"""


@dataclass
class Issue:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # SECURITY, PERFORMANCE, BEST_PRACTICE
    filepath: str
    line_num: int
    content: str
    message: str
    suggestion: str


class ScannerEngine:
    def __init__(self):
        self.issues: List[Issue] = []
        self.dockerfiles: List[Path] = []
        self.composefiles: List[Path] = []
        self.root_path = Path(".")
        self.stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "files_scanned": 0
        }

    def reset(self):
        self.issues = []
        self.dockerfiles = []
        self.composefiles = []
        self.stats = {k: 0 for k in self.stats}

    def spider_search(self, start_path: str):
        """Recursively finds all Docker infrastructure files."""
        self.root_path = Path(start_path)
        self.reset()

        try:
            for root, dirs, files in os.walk(start_path):
                # Skip common ignore folders
                if any(x in root for x in [".git", "node_modules", "venv", "__pycache__"]):
                    continue

                for file in files:
                    if file == "Dockerfile" or file.endswith(".Dockerfile"):
                        self.dockerfiles.append(Path(root) / file)
                    elif file in ["docker-compose.yml", "docker-compose.yaml"]:
                        self.composefiles.append(Path(root) / file)
        except PermissionError:
            rprint("[red]Permission Denied: Could not access some folders.[/red]")

    def analyze_all(self):
        """Runs the deep scan on all found files."""
        for df in self.dockerfiles:
            self._scan_dockerfile(df)
        for cf in self.composefiles:
            self._scan_compose(cf)

    def add_issue(self, severity, category, filepath, line, content, msg, fix):
        self.issues.append(Issue(severity, category, str(filepath), line, content, msg, fix))
        if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            self.stats[severity.lower()] += 1

    def _scan_dockerfile(self, filepath: Path):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except:
            return

        self.stats["files_scanned"] += 1
        has_user = False
        has_healthcheck = False

        for i, line in enumerate(lines):
            line_num = i + 1
            content = line.strip()
            if not content or content.startswith("#"): continue

            # --- SECURITY ---
            if "USER" in content.upper(): has_user = True
            if "HEALTHCHECK" in content.upper(): has_healthcheck = True

            if "sudo" in content.lower():
                self.add_issue("CRITICAL", "SECURITY", filepath, line_num, content, "Sudo used in build.",
                               "Remove 'sudo'. Build as root, drop privileges later.")

            if "apk add" in content and "--no-cache" not in content:
                self.add_issue("MEDIUM", "PERFORMANCE", filepath, line_num, content, "APK Cache not disabled.",
                               "Use 'apk add --no-cache ...' to reduce image size.")

            if (
                    "apt-get install" in content or "apt install" in content) and "rm -rf /var/lib/apt/lists" not in content:
                self.add_issue("MEDIUM", "PERFORMANCE", filepath, line_num, content, "APT Lists not cleaned.",
                               "Add '&& rm -rf /var/lib/apt/lists/*' to the same RUN command.")

            if "pip install" in content and "--no-cache-dir" not in content:
                self.add_issue("LOW", "PERFORMANCE", filepath, line_num, content, "Pip cache stored.",
                               "Use 'pip install --no-cache-dir' to save space.")

            if "EXPOSE 22" in content.upper():
                self.add_issue("CRITICAL", "SECURITY", filepath, line_num, content, "SSH Port Exposed.",
                               "Do not run SSH in containers. Use 'docker exec'.")

            # Secrets Detection
            if any(x in content.upper() for x in ["AWS_ACCESS_KEY", "SECRET_KEY", "PASSWORD="]):
                if "ARG" not in content and "ENV" in content:
                    self.add_issue("CRITICAL", "SECURITY", filepath, line_num, content, "Potential Hardcoded Secret.",
                                   "Use Docker Secrets or run-time ENVs.")

        if not has_user:
            self.add_issue("HIGH", "SECURITY", filepath, 0, "Global", "Running as Root.",
                           "Add 'USER <uid>' instruction.")
        if not has_healthcheck:
            self.add_issue("LOW", "BEST_PRACTICE", filepath, 0, "Global", "No Healthcheck.",
                           "Add HEALTHCHECK instruction for auto-recovery.")

    def _scan_compose(self, filepath: Path):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except:
            return

        self.stats["files_scanned"] += 1

        for i, line in enumerate(lines):
            line_num = i + 1
            content = line.strip()
            if not content or content.startswith("#"): continue

            if "/var/run/docker.sock" in content:
                self.add_issue("CRITICAL", "SECURITY", filepath, line_num, content, "Docker Socket Mounted.",
                               "This allows the container to delete all other containers. Avoid if possible.")

            if "privileged: true" in content:
                self.add_issue("CRITICAL", "SECURITY", filepath, line_num, content, "Privileged Mode.",
                               "Container has full host root capabilities. Extremely dangerous.")

            if "image:" in content and ":latest" in content:
                self.add_issue("HIGH", "RELIABILITY", filepath, line_num, content, "Using :latest tag.",
                               "Pin specific versions for production stability.")

            if "environment:" in content and "PASSWORD" in lines[min(i + 1, len(lines) - 1)].upper():
                self.add_issue("HIGH", "SECURITY", filepath, line_num, content, "Inline Environment Secrets.",
                               "Use an .env file or Docker Secrets.")


# --- UI COMPONENTS ---

engine = ScannerEngine()


def print_banner():
    if os.name == 'nt':
        os.system('cls')
    else:
        console.clear()

    console.print(BANNER)
    console.print(Text("  Ahmed Atef Elnadi | DevOps Solution Architect | GitHub: AhmedDev374", style="dim white",
                       justify="center"))
    console.print(Text("-" * 80, style="dim blue", justify="center"))


def loading_animation(task_name):
    with Progress(
            SpinnerColumn("aesthetic"),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=None),
            transient=True
    ) as progress:
        task = progress.add_task(task_name, total=100)
        while not progress.finished:
            progress.update(task, advance=random.uniform(1, 5))
            time.sleep(0.02)


def module_spider_scan():
    print_banner()
    path_input = Prompt.ask("[bold yellow][?] Enter root path to scan[/bold yellow]", default=".")

    loading_animation(f"Spidering directory: {path_input}")
    engine.spider_search(path_input)

    tree = Tree(f"📁 [bold]{Path(path_input).resolve().name}[/bold]")

    # Visualizing the found files
    for d in engine.dockerfiles:
        tree.add(f"{ICON_WHALE} [cyan]{d.relative_to(path_input)}[/cyan]")
    for c in engine.composefiles:
        tree.add(f"{ICON_OCTOPUS} [magenta]{c.relative_to(path_input)}[/magenta]")

    console.print(Panel(tree, title="[bold]Reconnaissance Results[/bold]", border_style="blue"))
    rprint(
        f"[bold green]Found {len(engine.dockerfiles)} Dockerfiles and {len(engine.composefiles)} Compose files.[/bold green]")
    Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")


def module_deep_analysis():
    if engine.stats["files_scanned"] == 0 and not engine.dockerfiles and not engine.composefiles:
        rprint(f"[bold red]{ICON_CROSS} No files loaded! Run the Spider Scan (Option 1) first.[/bold red]")
        time.sleep(2)
        return

    print_banner()
    loading_animation("Running Heuristic Analysis & Forensics Engine...")
    engine.analyze_all()

    # Sort issues by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_issues = sorted(engine.issues, key=lambda x: severity_order.get(x.severity, 99))

    table = Table(title=f"{ICON_SHIELD} VULNERABILITY REPORT", expand=True, header_style="bold black on white")
    table.add_column("Sev", style="bold", width=8)
    table.add_column("File", style="dim", width=25)
    table.add_column("Issue Detected", style="white")
    table.add_column("Expert Solution", style="green")

    for issue in sorted_issues:
        color = "red" if issue.severity == "CRITICAL" else "yellow" if issue.severity == "HIGH" else "blue"

        # FIX: Display path relative to root
        try:
            rel_path = os.path.relpath(issue.filepath, engine.root_path)
        except ValueError:
            rel_path = Path(issue.filepath).name

        table.add_row(
            f"[{color}]{issue.severity}[/{color}]",
            f"{rel_path}:{issue.line_num}",
            issue.message,
            issue.suggestion
        )

    console.print(table)

    # Scorecard
    score = 100 - (engine.stats["critical"] * 15) - (engine.stats["high"] * 5) - (engine.stats["medium"] * 2)
    score = max(0, score)

    stats_panel = Panel(
        f"""
        [bold red]CRITICAL: {engine.stats['critical']}[/]   [bold yellow]HIGH: {engine.stats['high']}[/]   [bold blue]MEDIUM: {engine.stats['medium']}[/]

        [bold white on blue]  FINAL SYSTEM SCORE: {score}/100  [/]
        """,
        title="Session Statistics", border_style="white"
    )
    console.print(stats_panel)
    Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")


def module_fixer_preview():
    print_banner()
    rprint(f"[bold yellow]{ICON_FIX} AUTO-FIX PREVIEW MODULE[/bold yellow]")

    if not engine.issues:
        rprint("[dim]No issues to fix. Run analysis first.[/dim]")
        time.sleep(2)
        return

    for issue in engine.issues:
        if issue.line_num > 0:
            console.print(Panel(
                f"[red]- {issue.content}[/red]\n[green]+ {issue.suggestion}[/green]",
                title=f"{Path(issue.filepath).name} : Line {issue.line_num}",
                subtitle=issue.category
            ))

    Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")


def module_topology_map():
    print_banner()
    rprint(f"[bold cyan]{ICON_MAP}  INFRASTRUCTURE TOPOLOGY MAP[/bold cyan]")

    if not engine.composefiles:
        rprint("[dim]No compose files found. Cannot map topology.[/dim]")
        time.sleep(2)
        return

    # A simple parser to visualize services
    for cf in engine.composefiles:
        tree = Tree(f"{ICON_OCTOPUS} [bold magenta]{cf.name}[/bold magenta]")
        try:
            with open(cf, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    # Naive service detection
                    if ":" in line and len(line.split(":")) == 2 and not line.startswith("-") and "version" not in line:
                        # Check indentation in real usage, here we approximate
                        if not any(k in line for k in ["image", "build", "ports", "volumes", "environment"]):
                            service_node = tree.add(f"{ICON_PACKAGE} [bold green]{line.replace(':', '')}[/bold green]")
        except:
            pass
        console.print(tree)
        console.print("")

    Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")


def module_export():
    if not engine.issues and engine.stats["files_scanned"] == 0:
        rprint("[red]No data to export. Run a scan first.[/red]")
        time.sleep(1.5)
        return

    rprint("[bold yellow]Generating HTML Report...[/bold yellow]")

    score = 100 - (engine.stats["critical"] * 15) - (engine.stats["high"] * 5) - (engine.stats["medium"] * 2)
    score = max(0, score)
    score_color = "#28a745" if score > 80 else "#ffc107" if score > 50 else "#dc3545"

    html_rows = ""
    for issue in engine.issues:
        # Determine Color Class
        if issue.severity == "CRITICAL":
            color_class = "critical"
        elif issue.severity == "HIGH":
            color_class = "high"
        elif issue.severity == "MEDIUM":
            color_class = "medium"
        else:
            color_class = "low"

        # FIX: Relative Path Calculation
        try:
            rel_path = os.path.relpath(issue.filepath, engine.root_path)
        except ValueError:
            rel_path = Path(issue.filepath).name

        row = f"""
        <tr>
            <td><span class="badge {color_class}">{issue.severity}</span></td>
            <td>{issue.category}</td>
            <td class="location">{rel_path}:{issue.line_num}</td>
            <td>{issue.message}</td>
            <td class="fix-code">{issue.suggestion}</td>
        </tr>
        """
        html_rows += row

    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DevOps Security Audit Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #e0e0e0; margin: 0; padding: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
            .logo h1 {{ margin: 0; color: #00bcd4; text-transform: uppercase; letter-spacing: 2px; }}
            .score-card {{ text-align: right; }}
            .score-circle {{ display: inline-block; width: 60px; height: 60px; border-radius: 50%; background: {score_color}; color: white; text-align: center; line-height: 60px; font-weight: bold; font-size: 24px; }}
            .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
            .metric-box {{ background: #252526; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333; }}
            .metric-count {{ font-size: 36px; font-weight: bold; margin-bottom: 5px; }}

            /* COLORS */
            .critical-text {{ color: #dc3545; }} 
            .high-text {{ color: #fd7e14; }} 
            .medium-text {{ color: #ffc107; }} 
            .low-text {{ color: #0dcaf0; }}

            table {{ width: 100%; border-collapse: collapse; background: #252526; border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #333; }}
            th {{ background: #333; color: #fff; text-transform: uppercase; font-size: 12px; letter-spacing: 1px; }}
            tr:hover {{ background: #2a2d2e; }}

            .badge {{ padding: 5px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }}
            .badge.critical {{ background: #dc3545; }} /* Red */
            .badge.high {{ background: #fd7e14; }}     /* Orange */
            .badge.medium {{ background: #ffc107; color: black; }} /* Yellow */
            .badge.low {{ background: #0dcaf0; color: black; }}    /* Blue */

            .location {{ font-family: monospace; color: #bbb; }}
            .fix-code {{ font-family: 'Consolas', monospace; color: #a6e22e; background: #111; padding: 5px 10px; border-radius: 4px; }}
            .footer {{ margin-top: 50px; text-align: center; color: #666; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">
                    <h1>The Architect's Console</h1>
                    <p>Infrastructure Security Audit</p>
                </div>
                <div class="score-card">
                    <span>System Health Score</span>
                    <div class="score-circle">{score}</div>
                </div>
            </div>

            <div class="metrics-grid">
                <div class="metric-box">
                    <div class="metric-count critical-text">{engine.stats['critical']}</div>
                    <div>Critical</div>
                </div>
                <div class="metric-box">
                    <div class="metric-count high-text">{engine.stats['high']}</div>
                    <div>High</div>
                </div>
                <div class="metric-box">
                    <div class="metric-count medium-text">{engine.stats['medium']}</div>
                    <div>Medium</div>
                </div>
                <div class="metric-box">
                    <div class="metric-count low-text">{engine.stats['low']}</div>
                    <div>Low</div>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>File Location</th>
                        <th>Issue Detected</th>
                        <th>Recommended Fix</th>
                    </tr>
                </thead>
                <tbody>
                    {html_rows}
                </tbody>
            </table>

            <div class="footer">
                Generated by DevOps Architect Console • {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </div>
    </body>
    </html>
    """

    with open("audit_report.html", "w", encoding="utf-8") as f:
        f.write(html_template)

    rprint(f"[bold green]{ICON_CHECK} Report exported successfully: ./audit_report.html[/bold green]")
    webbrowser.open("file://" + os.path.realpath("audit_report.html"))
    Prompt.ask("\n[dim]Press Enter to return...[/dim]")


# --- MAIN MENU LOOP ---

def main_menu():
    while True:
        print_banner()

        menu_text = f"""
    [bold white]SELECT A MODULE:[/bold white]

    [bold cyan][1][/bold cyan] {ICON_SPIDER}  Spider Scan (Discover Files)    [dim]Recursive directory crawler[/dim]
    [bold cyan][2][/bold cyan] {ICON_SCOPE}  Deep Analysis (The Detective)   [dim]Security & Logic forensics[/dim]
    [bold cyan][3][/bold cyan] {ICON_MAP}  Topology Mapper                 [dim]Visual service graph[/dim]
    [bold cyan][4][/bold cyan] {ICON_FIX}  Auto-Fix Preview                [dim]Generate patch suggestions[/dim]
    [bold cyan][5][/bold cyan] {ICON_CHART}  Export Report                   [dim]Generate HTML Dashboard[/dim]

    [bold red][99] Exit Console[/bold red]
        """
        console.print(Panel(menu_text, border_style="blue", title="Main Operations"))

        choice = IntPrompt.ask("[bold yellow]root@docker-detective:~#[/bold yellow]",
                               choices=["1", "2", "3", "4", "5", "99"])

        if choice == 1:
            module_spider_scan()
        elif choice == 2:
            module_deep_analysis()
        elif choice == 3:
            module_topology_map()
        elif choice == 4:
            module_fixer_preview()
        elif choice == 5:
            module_export()
        elif choice == 99:
            rprint("[bold red]Exiting... Stay Secure.[/bold red]")
            sys.exit()


if __name__ == "__main__":
    if os.name == 'nt':
        os.system("")

    try:
        main_menu()
    except KeyboardInterrupt:
        rprint("\n[bold red]Force Quit Detected.[/bold red]")
        sys.exit()