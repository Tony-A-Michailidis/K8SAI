"""
Configuration management for K8s AI Log Analyzer
"""

from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseSettings, Field
from pydantic_settings import BaseSettings as Settings
import yaml
import os


class ClusterConfig(Settings):
    """Kubernetes cluster configuration"""
    
    name: str = Field(default="default", description="Cluster name for identification")
    kubeconfig_path: Optional[str] = Field(default=None, description="Path to kubeconfig file")
    context: Optional[str] = Field(default=None, description="Kubernetes context to use")
    namespaces: List[str] = Field(default_factory=lambda: ["default"], description="Namespaces to monitor")
    exclude_namespaces: List[str] = Field(default_factory=lambda: ["kube-system"], description="Namespaces to exclude")
    
    class Config:
        env_prefix = "K8S_"


class ClaudeConfig(Settings):
    """Claude AI configuration"""
    
    api_key: Optional[str] = Field(default=None, description="Anthropic API key")
    model: str = Field(default="claude-3-5-sonnet-20241022", description="Claude model to use")
    max_tokens: int = Field(default=4096, description="Maximum tokens per request")
    temperature: float = Field(default=0.1, description="Model temperature")
    
    class Config:
        env_prefix = "ANTHROPIC_"


class AnalysisConfig(Settings):
    """Analysis engine configuration"""
    
    batch_size: int = Field(default=100, description="Number of log entries to analyze per batch")
    analysis_interval: int = Field(default=60, description="Analysis interval in seconds")
    max_log_age: int = Field(default=3600, description="Maximum log age in seconds")
    
    # Analysis types to enable
    error_detection: bool = Field(default=True, description="Enable error detection")
    performance_analysis: bool = Field(default=True, description="Enable performance analysis")
    security_analysis: bool = Field(default=True, description="Enable security analysis")
    resource_analysis: bool = Field(default=True, description="Enable resource usage analysis")
    natural_language_summary: bool = Field(default=True, description="Generate natural language summaries")
    troubleshooting_suggestions: bool = Field(default=True, description="Generate troubleshooting suggestions")


class AlertConfig(Settings):
    """Alerting and reporting configuration"""
    
    enable_console_output: bool = Field(default=True, description="Enable console output")
    enable_file_output: bool = Field(default=True, description="Enable file output")
    output_dir: str = Field(default="./outputs", description="Output directory")
    
    # Alert thresholds
    error_threshold: int = Field(default=5, description="Error count threshold for alerts")
    performance_threshold: float = Field(default=0.8, description="Performance threshold for alerts")
    security_alert_enabled: bool = Field(default=True, description="Enable security alerts")


class AppConfig(Settings):
    """Main application configuration"""
    
    # Core settings
    debug: bool = Field(default=False, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # Component configurations
    cluster: ClusterConfig = Field(default_factory=ClusterConfig)
    claude: ClaudeConfig = Field(default_factory=ClaudeConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    
    class Config:
        env_prefix = "K8SAI_"


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """
    Load configuration from YAML file and environment variables
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        AppConfig instance with loaded configuration
    """
    config_data = {}
    
    # Load from YAML file if provided
    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f) or {}
    
    # Create config with YAML data (env vars will override)
    config = AppConfig(**config_data)
    
    # Ensure API key is set
    if not config.claude.api_key:
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if api_key:
            config.claude.api_key = api_key
    
    return config


def save_example_config(output_path: str) -> None:
    """
    Save an example configuration file
    
    Args:
        output_path: Path where to save the example config
    """
    example_config = {
        'debug': False,
        'log_level': 'INFO',
        'cluster': {
            'name': 'my-aks-cluster',
            'kubeconfig_path': '~/.kube/config',
            'context': 'my-aks-context',
            'namespaces': ['default', 'production', 'staging'],
            'exclude_namespaces': ['kube-system', 'kube-public']
        },
        'claude': {
            'model': 'claude-3-5-sonnet-20241022',
            'max_tokens': 4096,
            'temperature': 0.1
        },
        'analysis': {
            'batch_size': 100,
            'analysis_interval': 60,
            'max_log_age': 3600,
            'error_detection': True,
            'performance_analysis': True,
            'security_analysis': True,
            'resource_analysis': True,
            'natural_language_summary': True,
            'troubleshooting_suggestions': True
        },
        'alerts': {
            'enable_console_output': True,
            'enable_file_output': True,
            'output_dir': './outputs',
            'error_threshold': 5,
            'performance_threshold': 0.8,
            'security_alert_enabled': True
        }
    }
    
    with open(output_path, 'w') as f:
        yaml.dump(example_config, f, default_flow_style=False, indent=2)


if __name__ == "__main__":
    # Generate example config
    save_example_config("config/config.example.yaml")
    print("Example configuration saved to config/config.example.yaml")