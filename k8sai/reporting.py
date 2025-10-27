"""
Reporting and alerting system for K8s AI analysis results
Handles console output, file output, and various alert formats
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import structlog
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich import box

from .claude_analyzer import AnalysisResult, AnalysisType

logger = structlog.get_logger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OutputFormat(Enum):
    """Output format types"""
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PLAIN_TEXT = "plain_text"


@dataclass
class AlertRule:
    """Alert rule configuration"""
    name: str
    condition: str  # e.g., "error_count > 5"
    severity: AlertSeverity
    message_template: str
    enabled: bool = True


class ReportingSystem:
    """Main reporting and alerting system"""
    
    def __init__(self, 
                 console_output: bool = True,
                 file_output: bool = True,
                 output_dir: str = "./outputs"):
        """
        Initialize reporting system
        
        Args:
            console_output: Enable console output
            file_output: Enable file output
            output_dir: Directory for output files
        """
        self.console_output = console_output
        self.file_output = file_output
        self.output_dir = Path(output_dir)
        
        # Create output directory
        if self.file_output:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Rich console
        self.console = Console() if console_output else None
        
        # Default alert rules
        self.alert_rules = [
            AlertRule(
                name="High Error Count",
                condition="error_count >= 10",
                severity=AlertSeverity.HIGH,
                message_template="High number of errors detected: {error_count} errors found"
            ),
            AlertRule(
                name="Critical Security Issue",
                condition="security_threats > 0 and max_severity == 'critical'",
                severity=AlertSeverity.CRITICAL,
                message_template="Critical security threats detected: {security_summary}"
            ),
            AlertRule(
                name="Performance Degradation",
                condition="performance_issues > 3",
                severity=AlertSeverity.MEDIUM,
                message_template="Performance issues detected: {performance_summary}"
            )
        ]
        
        logger.info("Initialized reporting system", 
                   console=console_output, 
                   file_output=file_output,
                   output_dir=str(self.output_dir))
    
    def _generate_timestamp_prefix(self) -> str:
        """Generate timestamp prefix for files"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _save_to_file(self, content: str, filename: str, format_type: OutputFormat = OutputFormat.JSON):
        """Save content to file"""
        if not self.file_output:
            return
        
        try:
            timestamp = self._generate_timestamp_prefix()
            
            # Add appropriate extension based on format
            extensions = {
                OutputFormat.JSON: ".json",
                OutputFormat.MARKDOWN: ".md",
                OutputFormat.HTML: ".html",
                OutputFormat.PLAIN_TEXT: ".txt"
            }
            
            ext = extensions.get(format_type, ".txt")
            full_filename = f"{timestamp}_{filename}{ext}"
            file_path = self.output_dir / full_filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info("Saved report to file", file=str(file_path))
            
        except Exception as e:
            logger.error("Failed to save report to file", filename=filename, error=str(e))
    
    def format_analysis_results_json(self, 
                                   analysis_data: Dict[str, Any]) -> str:
        """Format analysis results as JSON"""
        return json.dumps(analysis_data, indent=2, default=str)
    
    def format_analysis_results_markdown(self, 
                                       analysis_data: Dict[str, Any]) -> str:
        """Format analysis results as Markdown"""
        md_lines = []
        
        # Header
        md_lines.append("# K8s AI Log Analysis Report")
        md_lines.append(f"**Generated:** {analysis_data.get('timestamp', 'Unknown')}")
        md_lines.append(f"**Status:** {analysis_data.get('status', 'Unknown')}")
        md_lines.append(f"**Logs Analyzed:** {analysis_data.get('logs_collected', 0)}")
        md_lines.append(f"**Duration:** {analysis_data.get('duration_seconds', 0):.2f} seconds")
        md_lines.append("")
        
        # Analysis Results
        results = analysis_data.get('analysis_results', [])
        
        if not results:
            md_lines.append("## No Analysis Results")
            md_lines.append("No analysis results were generated.")
            return "\n".join(md_lines)
        
        for result in results:
            analysis_type = result.get('analysis_type', 'Unknown')
            md_lines.append(f"## {analysis_type.replace('_', ' ').title()}")
            
            # Summary
            summary = result.get('summary', '')
            if summary:
                md_lines.append(f"**Summary:** {summary}")
                md_lines.append("")
            
            # Confidence
            confidence = result.get('confidence', 0)
            md_lines.append(f"**Confidence:** {confidence:.2%}")
            md_lines.append("")
            
            # Findings
            findings = result.get('findings', [])
            if findings:
                md_lines.append("### Findings")
                for i, finding in enumerate(findings, 1):
                    md_lines.append(f"{i}. **{finding.get('error_type', finding.get('issue_type', finding.get('threat_type', 'Finding')))}**")
                    
                    description = finding.get('description', '')
                    if description:
                        md_lines.append(f"   - {description}")
                    
                    severity = finding.get('severity', '')
                    if severity:
                        md_lines.append(f"   - **Severity:** {severity}")
                    
                md_lines.append("")
            
            # Suggestions
            suggestions = result.get('suggestions', [])
            if suggestions:
                md_lines.append("### Recommendations")
                for suggestion in suggestions:
                    md_lines.append(f"- {suggestion}")
                md_lines.append("")
        
        return "\n".join(md_lines)
    
    def display_console_summary(self, analysis_data: Dict[str, Any]):
        """Display analysis summary in console using Rich"""
        if not self.console:
            return
        
        # Main status panel
        status = analysis_data.get('status', 'unknown')
        status_color = {
            'success': 'green',
            'error': 'red',
            'no_logs': 'yellow'
        }.get(status, 'white')
        
        title = f"[bold]K8s AI Log Analysis[/bold]"
        content = f"""
[bold]Status:[/bold] [{status_color}]{status}[/{status_color}]
[bold]Timestamp:[/bold] {analysis_data.get('timestamp', 'Unknown')}
[bold]Logs Analyzed:[/bold] {analysis_data.get('logs_collected', 0)}
[bold]Duration:[/bold] {analysis_data.get('duration_seconds', 0):.2f} seconds
        """.strip()
        
        self.console.print(Panel(content, title=title, box=box.ROUNDED))
        
        # Analysis results
        results = analysis_data.get('analysis_results', [])
        
        if not results:
            self.console.print("[yellow]No analysis results generated[/yellow]")
            return
        
        for result in results:
            self._display_analysis_result(result)
    
    def _display_analysis_result(self, result: Dict[str, Any]):
        """Display a single analysis result in console"""
        analysis_type = result.get('analysis_type', 'Unknown')
        title = analysis_type.replace('_', ' ').title()
        
        # Summary
        summary = result.get('summary', 'No summary available')
        confidence = result.get('confidence', 0)
        
        content_lines = [
            f"[bold]Summary:[/bold] {summary}",
            f"[bold]Confidence:[/bold] {confidence:.1%}"
        ]
        
        # Key findings
        findings = result.get('findings', [])
        if findings:
            content_lines.append("\n[bold]Key Findings:[/bold]")
            for finding in findings[:3]:  # Show top 3 findings
                finding_type = finding.get('error_type', finding.get('issue_type', finding.get('threat_type', 'Finding')))
                severity = finding.get('severity', '')
                severity_color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'green'
                }.get(severity.lower(), 'white')
                
                content_lines.append(f"• [{severity_color}]{finding_type}[/{severity_color}] ({severity})")
        
        # Top suggestions
        suggestions = result.get('suggestions', [])
        if suggestions:
            content_lines.append("\n[bold]Top Recommendations:[/bold]")
            for suggestion in suggestions[:2]:  # Show top 2 suggestions
                content_lines.append(f"• {suggestion}")
        
        content = "\n".join(content_lines)
        self.console.print(Panel(content, title=title, box=box.ROUNDED))
    
    def display_health_summary(self, health_data: Dict[str, Any]):
        """Display cluster health summary in console"""
        if not self.console:
            return
        
        status = health_data.get('status', 'unknown')
        status_color = {
            'healthy': 'green',
            'issues_detected': 'yellow',
            'error': 'red',
            'connection_failed': 'red'
        }.get(status, 'white')
        
        # Create summary table
        table = Table(title="Cluster Health Summary", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value")
        
        table.add_row("Status", f"[{status_color}]{status}[/{status_color}]")
        table.add_row("Timestamp", health_data.get('timestamp', 'Unknown'))
        
        if 'total_logs' in health_data:
            table.add_row("Total Logs (30min)", str(health_data['total_logs']))
            table.add_row("Error Logs", str(health_data['error_logs']))
            table.add_row("Active Namespaces", str(health_data['namespaces_active']))
            table.add_row("Active Pods", str(health_data['pods_active']))
        
        # Connection status
        connections = health_data.get('connections', {})
        if connections:
            table.add_row("", "")  # Separator
            for service, connected in connections.items():
                status_icon = "✅" if connected else "❌"
                table.add_row(f"{service.title()} Connection", status_icon)
        
        self.console.print(table)
        
        # Error analysis if available
        error_analysis = health_data.get('error_analysis')
        if error_analysis:
            self.console.print("\n[bold red]Error Analysis:[/bold red]")
            for analysis in error_analysis:
                if analysis.get('analysis_type') == 'error_detection':
                    self._display_analysis_result(analysis)
    
    def check_alerts(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if any alert conditions are met"""
        alerts = []
        
        # Extract metrics from analysis data
        metrics = self._extract_metrics(analysis_data)
        
        for rule in self.alert_rules:
            if not rule.enabled:
                continue
            
            try:
                # Simple condition evaluation (in production, use a safer approach)
                condition_met = eval(rule.condition, {"__builtins__": {}}, metrics)
                
                if condition_met:
                    alert = {
                        'rule_name': rule.name,
                        'severity': rule.severity.value,
                        'message': rule.message_template.format(**metrics),
                        'timestamp': datetime.now().isoformat(),
                        'metrics': metrics
                    }
                    alerts.append(alert)
                    
            except Exception as e:
                logger.warning("Failed to evaluate alert rule", rule=rule.name, error=str(e))
        
        return alerts
    
    def _extract_metrics(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metrics from analysis data for alert evaluation"""
        metrics = {
            'error_count': 0,
            'performance_issues': 0,
            'security_threats': 0,
            'max_severity': 'low',
            'total_logs': analysis_data.get('logs_collected', 0)
        }
        
        results = analysis_data.get('analysis_results', [])
        
        for result in results:
            analysis_type = result.get('analysis_type', '')
            findings = result.get('findings', [])
            
            if analysis_type == 'error_detection':
                metrics['error_count'] = len(findings)
            elif analysis_type == 'performance_analysis':
                metrics['performance_issues'] = len(findings)
            elif analysis_type == 'security_analysis':
                metrics['security_threats'] = len(findings)
                # Find highest severity
                for finding in findings:
                    severity = finding.get('severity', 'low').lower()
                    if severity == 'critical':
                        metrics['max_severity'] = 'critical'
                    elif severity == 'high' and metrics['max_severity'] not in ['critical']:
                        metrics['max_severity'] = 'high'
        
        # Add summary fields for templates
        if metrics['error_count'] > 0:
            error_result = next((r for r in results if r.get('analysis_type') == 'error_detection'), {})
            metrics['error_summary'] = error_result.get('summary', f"{metrics['error_count']} errors detected")
        
        if metrics['security_threats'] > 0:
            security_result = next((r for r in results if r.get('analysis_type') == 'security_analysis'), {})
            metrics['security_summary'] = security_result.get('summary', f"{metrics['security_threats']} threats detected")
        
        if metrics['performance_issues'] > 0:
            perf_result = next((r for r in results if r.get('analysis_type') == 'performance_analysis'), {})
            metrics['performance_summary'] = perf_result.get('summary', f"{metrics['performance_issues']} issues detected")
        
        return metrics
    
    def display_alerts(self, alerts: List[Dict[str, Any]]):
        """Display alerts in console"""
        if not alerts or not self.console:
            return
        
        self.console.print("\n[bold red]🚨 ALERTS TRIGGERED 🚨[/bold red]")
        
        for alert in alerts:
            severity = alert['severity']
            color = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'green'
            }.get(severity, 'white')
            
            content = f"""
[bold]Rule:[/bold] {alert['rule_name']}
[bold]Severity:[/bold] [{color}]{severity.upper()}[/{color}]
[bold]Message:[/bold] {alert['message']}
[bold]Time:[/bold] {alert['timestamp']}
            """.strip()
            
            self.console.print(Panel(content, title=f"[{color}]ALERT[/{color}]", box=box.HEAVY))
    
    def generate_report(self, 
                       analysis_data: Dict[str, Any],
                       format_type: OutputFormat = OutputFormat.MARKDOWN,
                       save_to_file: bool = True) -> str:
        """
        Generate a formatted report
        
        Args:
            analysis_data: Analysis results data
            format_type: Output format
            save_to_file: Whether to save to file
            
        Returns:
            Formatted report content
        """
        if format_type == OutputFormat.JSON:
            content = self.format_analysis_results_json(analysis_data)
        elif format_type == OutputFormat.MARKDOWN:
            content = self.format_analysis_results_markdown(analysis_data)
        else:
            # Default to markdown for unsupported formats
            content = self.format_analysis_results_markdown(analysis_data)
        
        if save_to_file:
            self._save_to_file(content, "analysis_report", format_type)
        
        return content
    
    def process_analysis_results(self, analysis_data: Dict[str, Any]):
        """
        Main method to process analysis results - console display, file output, alerts
        
        Args:
            analysis_data: Complete analysis results
        """
        try:
            # Console output
            if self.console_output:
                self.display_console_summary(analysis_data)
            
            # File output
            if self.file_output:
                # Save JSON version
                self.generate_report(analysis_data, OutputFormat.JSON, save_to_file=True)
                # Save Markdown version
                self.generate_report(analysis_data, OutputFormat.MARKDOWN, save_to_file=True)
            
            # Check and display alerts
            alerts = self.check_alerts(analysis_data)
            if alerts:
                self.display_alerts(alerts)
                
                # Save alerts to file
                if self.file_output:
                    alerts_content = json.dumps(alerts, indent=2, default=str)
                    self._save_to_file(alerts_content, "alerts", OutputFormat.JSON)
            
            logger.info("Processed analysis results", 
                       console_output=self.console_output,
                       file_output=self.file_output,
                       alerts_triggered=len(alerts))
            
        except Exception as e:
            logger.error("Failed to process analysis results", error=str(e))


# Convenience functions

def create_basic_reporter(output_dir: str = "./outputs") -> ReportingSystem:
    """Create a basic reporting system with standard settings"""
    return ReportingSystem(
        console_output=True,
        file_output=True,
        output_dir=output_dir
    )


def create_console_only_reporter() -> ReportingSystem:
    """Create a reporter that only outputs to console"""
    return ReportingSystem(
        console_output=True,
        file_output=False
    )


if __name__ == "__main__":
    # Example usage
    reporter = create_basic_reporter()
    
    # Example analysis data
    sample_data = {
        'timestamp': datetime.now().isoformat(),
        'status': 'success',
        'logs_collected': 150,
        'duration_seconds': 45.2,
        'analysis_results': [
            {
                'analysis_type': 'error_detection',
                'summary': 'Found 3 critical errors in web application',
                'confidence': 0.92,
                'findings': [
                    {
                        'error_type': 'Database Connection Error',
                        'severity': 'high',
                        'description': 'Multiple database connection failures detected'
                    }
                ],
                'suggestions': [
                    'Check database connectivity',
                    'Review connection pool settings'
                ]
            }
        ]
    }
    
    reporter.process_analysis_results(sample_data)