# K8s AI Log Analyzer

An intelligent AKS/Kubernetes log analysis system, written with the help of Claude Sonnet 4.5, that uses Claude AI to automatically interpret cluster logs, detect anomalies, identify security threats, and provide actionable troubleshooting suggestions. Some configuration required, mostly self-explanatory for seasoned coders. If your logs contain sensitive data, and exposing them violate your company's IT Security and Privacy Policies, don't use it! Bring your own API key.


## 🌟 Features

- 🔍 **Comprehensive Log Collection**: Monitors all cluster logs via kubectl
- 🤖 **AI-Powered Analysis**: Uses Claude for intelligent log interpretation
- 🛡️ **Multi-Modal Detection**: Error classification, performance anomalies, security threats
- 📊 **Resource Analysis**: Pattern detection and usage insights
- 💬 **Natural Language Summaries**: Human-readable interpretations of log events
- 🔧 **Automated Suggestions**: Troubleshooting recommendations and remediation steps
- ⚙️ **Configurable**: Generic deployment with cluster-specific configurations
- 📈 **Real-time Monitoring**: Continuous analysis with customizable intervals
- 🎯 **Smart Alerting**: Configurable thresholds and alert rules

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository and navigate to it
cd k8sai

# Install dependencies
pip install -r requirements.txt

# Install the tool
pip install -e .
```

### 2. Configuration

```bash
# Generate example configuration
k8sai init-config

# Copy and customize configuration
cp config/config.example.yaml config/config.yaml
```

Edit `config/config.yaml` with your settings:
- AKS cluster context and namespaces
- Claude API configuration
- Analysis preferences

### 3. Set Your Claude API Key

```bash
export ANTHROPIC_API_KEY="your_claude_api_key_here"
```

### 4. Test Your Setup

```bash
# Test connections to Kubernetes and Claude
k8sai test

# Check cluster health
k8sai health
```

### 5. Run Analysis

```bash
# Single analysis run
k8sai analyze

# Quick analysis of recent logs
k8sai quick --hours 2

# Continuous monitoring
k8sai monitor
```

## 📖 Documentation

- **[Complete Usage Guide](USAGE_GUIDE.md)** - Comprehensive setup and usage instructions
- **[Configuration Reference](config/config.example.yaml)** - All available configuration options

## Configuration

The system is designed to be generic but configurable for specific clusters. See `config/config.example.yaml` for all available options.

## Architecture

- **Log Collector**: Interfaces with kubectl to gather cluster logs
- **AI Engine**: Claude integration for intelligent analysis
- **Analysis Pipeline**: Multi-stage processing for different types of insights
- **Reporting System**: Configurable output formats and alerting

## License

MIT License
