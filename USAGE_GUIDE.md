# K8s AI Usage Guide

This guide will walk you through setting up and using the K8s AI Log Analyzer to monitor and analyze your AKS/Kubernetes cluster logs.

## Prerequisites

1. **Python 3.8+** installed on your system
2. **kubectl** configured to access your AKS cluster
3. **Claude API access** (Anthropic account with API key)
4. **AKS cluster** running and accessible

## Installation

### Option 1: Development Setup

```bash
# Clone or navigate to the project directory
cd k8sai

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Option 2: Direct Installation

```bash
# Install directly from source
pip install -e .
```

## Configuration

### 1. Generate Example Configuration

```bash
k8sai init-config
```

This creates `config/config.example.yaml`. Copy it to your working configuration:

```bash
cp config/config.example.yaml config/config.yaml
```

### 2. Configure Your Settings

Edit `config/config.yaml`:

```yaml
# Basic settings
debug: false
log_level: INFO

# Your AKS cluster configuration
cluster:
  name: my-aks-cluster
  kubeconfig_path: ~/.kube/config
  context: my-aks-context  # Your AKS context name
  namespaces:
    - default
    - production
    - staging
  exclude_namespaces:
    - kube-system
    - kube-public

# Claude AI settings
claude:
  model: claude-3-5-sonnet-20241022
  max_tokens: 4096
  temperature: 0.1

# Analysis configuration
analysis:
  batch_size: 100
  analysis_interval: 60  # seconds
  max_log_age: 3600      # 1 hour
  
  # Enable the types of analysis you want
  error_detection: true
  performance_analysis: true
  security_analysis: true
  resource_analysis: true
  natural_language_summary: true
  troubleshooting_suggestions: true

# Output and alerting
alerts:
  enable_console_output: true
  enable_file_output: true
  output_dir: ./outputs
  error_threshold: 5
```

### 3. Set Environment Variables

Create a `.env` file (or set environment variables):

```bash
# Required: Your Claude API key
ANTHROPIC_API_KEY=your_claude_api_key_here

# Optional: Override config settings
KUBECONFIG=~/.kube/config
K8S_CONTEXT=my-aks-context
```

## Getting Your AKS Context

Find your AKS context name:

```bash
kubectl config get-contexts
```

Look for your AKS cluster in the output and use the NAME column value in your configuration.

## Usage

### 1. Test Your Setup

Before running analysis, test your connections:

```bash
k8sai test
```

This will verify:
- ✅ kubectl can connect to your cluster
- ✅ Claude API is accessible
- ✅ Configuration is valid

### 2. Check Cluster Health

Get a quick health overview:

```bash
k8sai health
```

This shows:
- Active namespaces and pods
- Recent error counts
- Overall cluster status
- Quick error analysis if issues are found

### 3. Run Single Analysis

Analyze current logs once:

```bash
k8sai analyze
```

This will:
- Collect recent logs from all monitored namespaces
- Run AI analysis on the logs
- Display results in console
- Save detailed reports to `outputs/` directory

### 4. Quick Analysis Options

Analyze specific time ranges or error logs only:

```bash
# Analyze last 2 hours of logs
k8sai quick --hours 2

# Analyze only error logs from last hour
k8sai quick --hours 1 --errors-only
```

### 5. Continuous Monitoring

Start continuous monitoring mode:

```bash
k8sai monitor
```

This runs continuously and:
- Analyzes logs every 60 seconds (configurable)
- Shows real-time analysis results
- Triggers alerts when issues are detected
- Saves all reports to files
- Press Ctrl+C to stop

## Understanding the Output

### Console Output

The analyzer displays results in several sections:

#### 1. Analysis Summary
- Status (success/error/no_logs)
- Number of logs analyzed
- Processing time

#### 2. Individual Analysis Results
For each enabled analysis type:

- **Error Detection**: Finds and classifies errors
- **Performance Analysis**: Identifies performance bottlenecks
- **Security Analysis**: Detects potential security issues
- **Resource Analysis**: Analyzes resource usage patterns
- **Natural Language Summary**: Human-readable overview
- **Troubleshooting Suggestions**: Actionable recommendations

#### 3. Alerts
When configured thresholds are exceeded:
- 🚨 Alert notifications with severity levels
- Specific recommendations for resolution

### File Output

Reports are saved to `outputs/` directory with timestamps:

- `YYYYMMDD_HHMMSS_analysis_report.json` - Complete analysis data
- `YYYYMMDD_HHMMSS_analysis_report.md` - Human-readable report
- `YYYYMMDD_HHMMSS_alerts.json` - Alert details (if any)

## Common Use Cases

### 1. Troubleshooting Application Issues

```bash
# Quick check for recent errors
k8sai quick --errors-only

# Full analysis of specific timeframe
k8sai quick --hours 4
```

### 2. Security Monitoring

Enable security analysis in config and run:

```bash
k8sai monitor  # Continuous security monitoring
```

### 3. Performance Monitoring

For performance issues:

```bash
# Focus on performance analysis
k8sai analyze  # Will include performance analysis
```

### 4. Daily Health Checks

Add to your daily routine:

```bash
# Quick health check
k8sai health

# Overnight analysis
k8sai quick --hours 12
```

## Advanced Configuration

### Custom Analysis Intervals

For high-frequency monitoring:

```yaml
analysis:
  analysis_interval: 30  # Check every 30 seconds
  batch_size: 50        # Smaller batches for faster processing
```

### Namespace Filtering

Monitor specific namespaces:

```yaml
cluster:
  namespaces:
    - production
    - staging
  exclude_namespaces:
    - kube-system
    - monitoring
    - logging
```

### Alert Customization

Adjust alert thresholds:

```yaml
alerts:
  error_threshold: 10      # Alert after 10 errors
  performance_threshold: 0.9  # Performance alert threshold
  security_alert_enabled: true
```

## Troubleshooting

### Connection Issues

If `k8sai test` fails:

1. **Kubectl issues**:
   ```bash
   kubectl cluster-info  # Test kubectl directly
   kubectl get pods --all-namespaces  # Test permissions
   ```

2. **Claude API issues**:
   - Verify your API key is correct
   - Check your Anthropic account has sufficient credits
   - Test with a simple request outside the tool

3. **Configuration issues**:
   - Verify YAML syntax in config file
   - Check file paths exist
   - Validate environment variables

### Performance Issues

If analysis is slow:

1. Reduce `batch_size` in configuration
2. Limit `namespaces` to critical ones only
3. Increase `analysis_interval` for less frequent checks
4. Use `--errors-only` for quicker analysis

### Too Many/Few Results

Adjust analysis sensitivity:

- **Too verbose**: Increase `error_threshold`, reduce `max_log_age`
- **Missing issues**: Lower thresholds, increase `batch_size`

## Integration Examples

### CI/CD Pipeline Integration

```bash
#!/bin/bash
# Add to your deployment pipeline

echo "Checking cluster health post-deployment..."
k8sai health

if [ $? -eq 0 ]; then
    echo "✅ Cluster health check passed"
    
    echo "Running deployment analysis..."
    k8sai quick --hours 1
else
    echo "❌ Cluster health issues detected"
    exit 1
fi
```

### Alerting Integration

The tool outputs structured JSON that can be consumed by monitoring systems:

```bash
# Get health data in JSON format
k8sai health > cluster_health.json

# Process alerts programmatically
cat outputs/*_alerts.json | jq '.[] | select(.severity == "critical")'
```

### Scheduled Monitoring

Set up cron job for regular monitoring:

```bash
# Add to crontab for hourly checks
0 * * * * cd /path/to/k8sai && k8sai quick --hours 1 >> /var/log/k8sai.log 2>&1
```

## Best Practices

1. **Start Small**: Begin with one namespace and expand
2. **Regular Testing**: Run `k8sai test` regularly to ensure connectivity
3. **Review Outputs**: Regularly check the `outputs/` directory for insights
4. **Tune Gradually**: Adjust thresholds based on your cluster's normal behavior
5. **Security**: Keep your Claude API key secure and rotate regularly
6. **Backup Config**: Version control your configuration files

## Support and Contributing

- Review logs in debug mode: `k8sai --debug analyze`
- Check the `outputs/` directory for detailed reports
- Monitor Claude API usage through Anthropic console
- Consider contributing improvements back to the project

## Next Steps

1. Set up monitoring for your production clusters
2. Customize alert rules for your specific use cases  
3. Integrate with your existing monitoring and alerting systems
4. Develop custom analysis workflows for your applications