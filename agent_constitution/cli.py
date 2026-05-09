"""CLI module for agent-constitution using Click."""

import sys
import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box

from agent_constitution.constitution import Constitution, create_sample_constitution
from agent_constitution.enforcer import Enforcer, PolicyViolationError
from agent_constitution.audit import AuditLogger
from agent_constitution.dashboard.server import run_server


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="agent-constitution")
@click.option(
    "--constitution",
    "-c",
    type=click.Path(exists=True),
    help="Path to constitution YAML file",
    envvar="AGENT_CONSTITUTION"
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, constitution: Optional[str], verbose: bool):
    """Agent Constitution - Policy enforcement framework for AI agents."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["constitution_path"] = constitution
    
    if constitution:
        try:
            ctx.obj["constitution"] = Constitution.from_yaml(constitution)
            if verbose:
                console.print(f"[green]Loaded constitution: {ctx.obj['constitution'].name}[/green]")
        except Exception as e:
            console.print(f"[red]Error loading constitution: {e}[/red]")
            sys.exit(1)


@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="constitution.yaml",
    help="Output file path"
)
@click.option("--sample", is_flag=True, help="Create a sample constitution")
def init(output: str, sample: bool):
    """Initialize a new constitution file."""
    output_path = Path(output)
    
    if output_path.exists():
        if not click.confirm(f"{output} already exists. Overwrite?"):
            console.print("Aborted.")
            return
    
    if sample:
        constitution = create_sample_constitution()
    else:
        constitution = Constitution(
            name="My Agent Constitution",
            description="Custom policy configuration",
            version="1.0"
        )
    
    constitution.to_yaml(output_path)
    console.print(f"[green]Created constitution: {output_path.absolute()}[/green]")
    
    if sample:
        console.print("\n[dim]This sample constitution includes:[/dim]")
        console.print(f"  • {len(constitution.policies)} policies")
        console.print(f"  • {sum(len(p.rules) for p in constitution.policies)} rules")


@cli.command()
@click.argument("constitution_path", type=click.Path(exists=True))
def validate(constitution_path: str):
    """Validate a constitution YAML file."""
    try:
        constitution = Constitution.from_yaml(constitution_path)
        
        console.print(Panel(
            f"[green]✓ Constitution is valid[/green]\n\n"
            f"Name: {constitution.name}\n"
            f"Version: {constitution.version}\n"
            f"Policies: {len(constitution.policies)}\n"
            f"Rules: {sum(len(p.rules) for p in constitution.policies)}",
            title="Validation Result",
            border_style="green"
        ))
        
        # Validate rule conditions
        errors = constitution.validate_conditions()
        if errors:
            console.print("\n[yellow]Condition validation warnings:[/yellow]")
            for error in errors:
                console.print(f"  • {error}")
        else:
            console.print("\n[green]✓ All rule conditions are valid[/green]")
            
    except Exception as e:
        console.print(Panel(
            f"[red]✗ Validation failed[/red]\n\n{str(e)}",
            title="Validation Error",
            border_style="red"
        ))
        sys.exit(1)


@cli.command()
@click.argument("constitution_path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def show(constitution_path: str, fmt: str):
    """Display constitution contents."""
    try:
        constitution = Constitution.from_yaml(constitution_path)
        
        if fmt == "json":
            console.print(json.dumps(constitution.model_dump(), indent=2, default=str))
            return
        
        # Table format
        console.print(Panel(
            f"[bold]{constitution.name}[/bold]\n"
            f"{constitution.description or 'No description'}\n"
            f"Version: {constitution.version}",
            title="Constitution",
            border_style="blue"
        ))
        
        # Policies
        for policy in constitution.policies:
            console.print(f"\n[bold cyan]Policy: {policy.name}[/bold cyan]")
            console.print(f"  Priority: {policy.priority}")
            console.print(f"  Enabled: {'Yes' if policy.enabled else 'No'}")
            console.print(f"  Rules: {len(policy.rules)}")
            
            if policy.rules:
                table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
                table.add_column("Rule", style="cyan")
                table.add_column("Condition")
                table.add_column("Action", style="green")
                table.add_column("Severity", style="yellow")
                
                for rule in policy.rules:
                    table.add_row(
                        rule.name,
                        rule.condition[:50] + "..." if len(rule.condition) > 50 else rule.condition,
                        rule.action,
                        rule.severity
                    )
                
                console.print(table)
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("tool_name")
@click.option("--arg", "-a", multiple=True, help="Tool arguments (key=value)")
@click.option("--constitution", "-c", type=click.Path(exists=True), required=True)
def check(tool_name: str, arg: tuple, constitution: str):
    """Check if a tool call would be allowed."""
    try:
        # Parse arguments
        tool_args = {}
        for a in arg:
            if "=" in a:
                key, value = a.split("=", 1)
                tool_args[key] = value
        
        # Load constitution and create enforcer
        const = Constitution.from_yaml(constitution)
        enforcer = Enforcer(constitution=const)
        
        # Check the tool
        result = enforcer.check(tool_name=tool_name, tool_args=tool_args)
        
        # Display result
        if result.allowed:
            console.print(Panel(
                f"[green]✓ Tool '{tool_name}' is ALLOWED[/green]",
                border_style="green"
            ))
        else:
            console.print(Panel(
                f"[red]✗ Tool '{tool_name}' is BLOCKED[/red]",
                border_style="red"
            ))
        
        if result.violations:
            console.print("\n[yellow]Violations:[/yellow]")
            for violation in result.violations:
                console.print(f"  • [bold]{violation.rule_name}[/bold]")
                console.print(f"    {violation.rule_description}")
                console.print(f"    Severity: {violation.severity}")
                console.print(f"    Action: {violation.action}")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", "-p", type=int, default=8000, help="Port to bind to")
@click.option("--constitution", "-c", type=click.Path(exists=True), help="Constitution file to load")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def dashboard(host: str, port: int, constitution: Optional[str], reload: bool):
    """Start the web dashboard."""
    console.print(Panel(
        f"[bold]Agent Constitution Dashboard[/bold]\n\n"
        f"Starting server on http://{host}:{port}",
        border_style="blue"
    ))
    
    try:
        run_server(
            host=host,
            port=port,
            constitution_path=constitution,
            reload=reload
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped[/yellow]")


@cli.command()
@click.option("--log-path", default="./audit_logs.jsonl", help="Path to audit log file")
@click.option("--limit", "-n", type=int, default=20, help="Number of entries to show")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit(log_path: str, limit: int, fmt: str):
    """View audit logs."""
    try:
        logger = AuditLogger(log_path=log_path)
        entries = list(logger.read_logs(limit=limit))
        
        if not entries:
            console.print("[dim]No audit entries found[/dim]")
            return
        
        if fmt == "json":
            for entry in entries:
                console.print(json.dumps(entry.to_dict(), default=str))
            return
        
        # Table format
        table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
        table.add_column("Timestamp", style="dim")
        table.add_column("Event")
        table.add_column("Tool", style="cyan")
        table.add_column("Action", style="green")
        table.add_column("Allowed")
        
        for entry in entries:
            allowed_str = "[green]✓[/green]" if entry.allowed else "[red]✗[/red]"
            table.add_row(
                entry.timestamp[:19] if entry.timestamp else "N/A",
                entry.event_type,
                entry.tool_name or "N/A",
                entry.action,
                allowed_str
            )
        
        console.print(table)
        console.print(f"\n[dim]Showing {len(entries)} entries from {log_path}[/dim]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("--constitution", "-c", type=click.Path(exists=True), help="Constitution file")
def stats(constitution: Optional[str]):
    """Show enforcement statistics."""
    try:
        if constitution:
            const = Constitution.from_yaml(constitution)
            enforcer = Enforcer(constitution=const)
            
            stats_data = enforcer.get_stats()
            
            console.print(Panel(
                f"[bold]Enforcement Statistics[/bold]\n\n"
                f"Total Violations: {stats_data['total_violations']}\n"
                f"By Severity:\n"
                f"  Low: {stats_data['by_severity'].get('low', 0)}\n"
                f"  Medium: {stats_data['by_severity'].get('medium', 0)}\n"
                f"  High: {stats_data['by_severity'].get('high', 0)}\n"
                f"  Critical: {stats_data['by_severity'].get('critical', 0)}\n"
                f"By Action:\n"
                f"  Block: {stats_data['by_action'].get('block', 0)}\n"
                f"  Allow: {stats_data['by_action'].get('allow', 0)}\n"
                f"  Log: {stats_data['by_action'].get('log', 0)}\n"
                f"  Notify: {stats_data['by_action'].get('notify', 0)}",
                border_style="blue"
            ))
        else:
            console.print("[yellow]No constitution loaded. Use --constitution to specify one.[/yellow]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("expression")
@click.option("--context", "-c", multiple=True, help="Context variables (key=value)")
def eval_expr(expression: str, context: tuple):
    """Test an expression evaluator (debug tool)."""
    from agent_constitution.rules.evaluator import evaluate_expression
    
    try:
        # Parse context
        ctx = {}
        for c in context:
            if "=" in c:
                key, value = c.split("=", 1)
                # Try to parse as int/float/bool
                try:
                    if value.lower() == "true":
                        ctx[key] = True
                    elif value.lower() == "false":
                        ctx[key] = False
                    elif "." in value:
                        ctx[key] = float(value)
                    else:
                        ctx[key] = int(value)
                except ValueError:
                    ctx[key] = value
        
        result = evaluate_expression(expression, ctx)
        
        console.print(Panel(
            f"[bold]Expression:[/bold] {expression}\n"
            f"[bold]Context:[/bold] {ctx}\n"
            f"[bold]Result:[/bold] [green]{result}[/green]",
            title="Expression Evaluation",
            border_style="green"
        ))
    
    except Exception as e:
        console.print(Panel(
            f"[bold]Expression:[/bold] {expression}\n"
            f"[bold]Error:[/bold] [red]{e}[/red]",
            title="Expression Evaluation Failed",
            border_style="red"
        ))


if __name__ == "__main__":
    cli()
