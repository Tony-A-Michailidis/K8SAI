"""
Main entry point for K8s AI Log Analyzer
Provides CLI interface and orchestrates the analysis workflow
"""

import asyncio
import sys
import signal
from pathlib import Path
from typing import Optional
import click
import structlog
from rich.console import Console

from .config import load_config, save_example_config, AppConfig
from .analysis_engine import K8sAIAnalysisEngine, quick_cluster_check, run_one_shot_analysis
from .reporting import ReportingSystem

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="ISO"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)
console = Console()


class K8sAIApp:
    """Main application class"""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.engine = K8sAIAnalysisEngine(config)
        self.reporter = ReportingSystem(
            console_output=config.alerts.enable_console_output,
            file_output=config.alerts.enable_file_output,
            output_dir=config.alerts.output_dir
        )
        self.running = False
    
    async def run_health_check(self) -> bool:
        """Run health check and display results"""
        console.print("[bold blue]🔍 Running health check...[/bold blue]")
        
        health_data = await self.engine.get_cluster_health_summary()
        self.reporter.display_health_summary(health_data)
        
        return health_data.get('status') in ['healthy', 'issues_detected']
    
    async def run_single_analysis(self):
        """Run a single analysis cycle"""
        console.print("[bold blue]🚀 Starting log analysis...[/bold blue]")
        
        analysis_data = await self.engine.run_single_analysis()
        self.reporter.process_analysis_results(analysis_data)
        
        return analysis_data
    
    async def run_continuous_mode(self):
        """Run continuous analysis mode"""
        console.print(f"[bold green]🔄 Starting continuous analysis mode...[/bold green]")
        console.print(f"Analysis interval: {self.config.analysis.analysis_interval} seconds")
        console.print("Press Ctrl+C to stop")
        
        self.running = True
        
        # Set up signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            console.print("\n[yellow]📢 Shutdown signal received, stopping gracefully...[/yellow]")
            self.running = False
            self.engine.stop_continuous_analysis()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Create a task for the continuous analysis
        analysis_task = asyncio.create_task(self.engine.run_continuous_analysis())
        
        # Create a task for processing results
        processing_task = asyncio.create_task(self._continuous_processing_loop())
        
        try:
            # Wait for either task to complete (shouldn't happen unless stopped)
            await asyncio.gather(analysis_task, processing_task, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False
            console.print("[green]✅ Analysis stopped successfully[/green]")
    
    async def _continuous_processing_loop(self):
        """Process results from continuous analysis"""
        while self.running:
            try:
                # In a real implementation, you'd get results from a queue or similar
                # For now, we'll just wait and let the engine handle its own processing
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
    
    async def test_connections(self) -> bool:
        """Test all connections"""
        console.print("[bold blue]🔧 Testing connections...[/bold blue]")
        
        connections = await self.engine.test_connections()
        
        # Display results
        for service, connected in connections.items():
            status_icon = "✅" if connected else "❌"
            status_text = "Connected" if connected else "Failed"
            color = "green" if connected else "red"
            
            console.print(f"{status_icon} {service.title()}: [{color}]{status_text}[/{color}]")
        
        all_connected = all(connections.values())
        
        if all_connected:
            console.print("[bold green]✅ All connections successful![/bold green]")
        else:
            console.print("[bold red]❌ Some connections failed. Check your configuration.[/bold red]")
        
        return all_connected


# CLI Commands

@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Path to configuration file')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def cli(ctx, config, debug):
    """K8s AI Log Analyzer - Intelligent Kubernetes log analysis with Claude AI"""
    
    # Load configuration
    try:
        app_config = load_config(config)
        if debug:
            app_config.debug = True
            app_config.log_level = "DEBUG"
        
        # Configure logging level
        import logging
        log_level = getattr(logging, app_config.log_level.upper(), logging.INFO)
        logging.basicConfig(level=log_level)
        
        ctx.ensure_object(dict)
        ctx.obj['config'] = app_config
        ctx.obj['app'] = K8sAIApp(app_config)
        
    except Exception as e:
        console.print(f"[red]❌ Configuration error: {str(e)}[/red]")
        console.print("💡 Try running 'k8sai init-config' to create a sample configuration.")
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', type=click.Path(), default='config/config.example.yaml',
              help='Output path for example configuration')
def init_config(output):
    """Generate example configuration file"""
    try:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        save_example_config(output)
        console.print(f"[green]✅ Example configuration saved to {output}[/green]")
        console.print("💡 Copy this file to config.yaml and customize for your environment.")
    except Exception as e:
        console.print(f"[red]❌ Failed to create configuration: {str(e)}[/red]")
        sys.exit(1)


@cli.command()
@click.pass_context
def test(ctx):
    """Test connections to Kubernetes and Claude API"""
    app = ctx.obj['app']
    
    async def run_test():
        return await app.test_connections()
    
    success = asyncio.run(run_test())
    sys.exit(0 if success else 1)


@cli.command()
@click.pass_context
def health(ctx):
    """Check cluster health and display summary"""
    app = ctx.obj['app']
    
    async def run_health():
        return await app.run_health_check()
    
    success = asyncio.run(run_health())
    sys.exit(0 if success else 1)


@cli.command()
@click.pass_context
def analyze(ctx):
    """Run a single log analysis"""
    app = ctx.obj['app']
    
    async def run_analysis():
        try:
            analysis_data = await app.run_single_analysis()
            return analysis_data.get('status') == 'success'
        except Exception as e:
            console.print(f"[red]❌ Analysis failed: {str(e)}[/red]")
            return False
    
    success = asyncio.run(run_analysis())
    sys.exit(0 if success else 1)


@cli.command()
@click.pass_context
def monitor(ctx):
    """Run continuous monitoring mode"""
    app = ctx.obj['app']
    
    async def run_monitor():
        try:
            # First check connections
            if not await app.test_connections():
                console.print("[red]❌ Connection tests failed. Cannot start monitoring.[/red]")
                return False
            
            # Run continuous mode
            await app.run_continuous_mode()
            return True
            
        except KeyboardInterrupt:
            console.print("\n[yellow]📢 Monitoring stopped by user[/yellow]")
            return True
        except Exception as e:
            console.print(f"[red]❌ Monitoring failed: {str(e)}[/red]")
            return False
    
    success = asyncio.run(run_monitor())
    sys.exit(0 if success else 1)


@cli.command()
@click.option('--hours', '-h', type=int, default=1, 
              help='Hours of logs to analyze (default: 1)')
@click.option('--errors-only', is_flag=True, 
              help='Analyze only error logs')
@click.pass_context
def quick(ctx, hours, errors_only):
    """Quick analysis of recent logs"""
    config = ctx.obj['config']
    
    async def run_quick():
        try:
            console.print(f"[bold blue]⚡ Quick analysis of last {hours} hour(s)...[/bold blue]")
            
            app = K8sAIApp(config)
            
            # Test connections first
            if not await app.test_connections():
                return False
            
            # Collect logs
            if errors_only:
                from .log_collector import collect_error_logs
                logs = await collect_error_logs(app.engine.log_collector, hours=hours)
                console.print(f"Collected {len(logs)} error logs")
            else:
                logs = await app.engine.collect_logs(hours_back=hours)
                console.print(f"Collected {len(logs)} total logs")
            
            if not logs:
                console.print("[yellow]⚠️  No logs found for analysis[/yellow]")
                return True
            
            # Analyze logs
            results = await app.engine.analyze_logs(logs)
            
            # Create analysis data structure
            analysis_data = {
                'timestamp': logs[0].timestamp.isoformat() if logs else '',
                'status': 'success',
                'logs_collected': len(logs),
                'analysis_results': [result.to_dict() for result in results],
                'duration_seconds': 0  # Not tracking for quick analysis
            }
            
            # Display results
            app.reporter.process_analysis_results(analysis_data)
            
            return True
            
        except Exception as e:
            console.print(f"[red]❌ Quick analysis failed: {str(e)}[/red]")
            return False
    
    success = asyncio.run(run_quick())
    sys.exit(0 if success else 1)


# Main function for direct execution
def main():
    """Main entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]💥 Unexpected error: {str(e)}[/red]")
        if '--debug' in sys.argv:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()