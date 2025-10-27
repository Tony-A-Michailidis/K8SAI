"""
Core analysis engine that orchestrates log collection and AI analysis
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import structlog

from .config import AppConfig, load_config
from .log_collector import KubectlLogCollector, LogEntry, collect_recent_logs, collect_error_logs
from .claude_analyzer import ClaudeAnalyzer, AnalysisResult, AnalysisType

logger = structlog.get_logger(__name__)


class K8sAIAnalysisEngine:
    """Main analysis engine that coordinates log collection and AI analysis"""
    
    def __init__(self, config: AppConfig):
        """
        Initialize the analysis engine
        
        Args:
            config: Application configuration
        """
        self.config = config
        
        # Initialize components
        self.log_collector = KubectlLogCollector(
            kubeconfig_path=config.cluster.kubeconfig_path,
            context=config.cluster.context,
            namespaces=config.cluster.namespaces if config.cluster.namespaces != ["default"] else None,
            exclude_namespaces=config.cluster.exclude_namespaces
        )
        
        if not config.claude.api_key:
            raise ValueError("Claude API key is required. Set ANTHROPIC_API_KEY environment variable or configure in YAML.")
        
        self.analyzer = ClaudeAnalyzer(
            api_key=config.claude.api_key,
            model=config.claude.model,
            max_tokens=config.claude.max_tokens,
            temperature=config.claude.temperature
        )
        
        # Analysis state
        self.running = False
        self.last_analysis_time = None
        
        logger.info("Initialized K8s AI Analysis Engine", 
                   cluster=config.cluster.name,
                   model=config.claude.model,
                   analysis_interval=config.analysis.analysis_interval)
    
    def get_enabled_analysis_types(self) -> List[AnalysisType]:
        """Get list of enabled analysis types from configuration"""
        enabled_types = []
        
        if self.config.analysis.error_detection:
            enabled_types.append(AnalysisType.ERROR_DETECTION)
        
        if self.config.analysis.performance_analysis:
            enabled_types.append(AnalysisType.PERFORMANCE_ANALYSIS)
        
        if self.config.analysis.security_analysis:
            enabled_types.append(AnalysisType.SECURITY_ANALYSIS)
        
        if self.config.analysis.resource_analysis:
            enabled_types.append(AnalysisType.RESOURCE_ANALYSIS)
        
        if self.config.analysis.natural_language_summary:
            enabled_types.append(AnalysisType.NATURAL_LANGUAGE_SUMMARY)
        
        if self.config.analysis.troubleshooting_suggestions:
            enabled_types.append(AnalysisType.TROUBLESHOOTING_SUGGESTIONS)
        
        return enabled_types
    
    async def test_connections(self) -> Dict[str, bool]:
        """Test connections to Kubernetes and Claude API"""
        results = {}
        
        # Test Kubernetes connection
        try:
            k8s_result = await self.log_collector.test_connection()
            results['kubernetes'] = k8s_result
        except Exception as e:
            logger.error("Kubernetes connection test failed", error=str(e))
            results['kubernetes'] = False
        
        # Test Claude API connection
        try:
            # Simple test with minimal log data
            test_logs = [LogEntry(
                timestamp=datetime.now(),
                namespace="test",
                pod_name="test-pod",
                container_name="test-container",
                message="Test log message",
                level="INFO"
            )]
            
            # Try a simple analysis
            await self.analyzer.generate_natural_language_summary(test_logs)
            results['claude'] = True
            
        except Exception as e:
            logger.error("Claude API connection test failed", error=str(e))
            results['claude'] = False
        
        return results
    
    async def collect_logs(self, 
                          hours_back: Optional[int] = None,
                          max_lines_per_pod: Optional[int] = None) -> List[LogEntry]:
        """
        Collect logs from the cluster
        
        Args:
            hours_back: Hours to look back (uses config default if None)
            max_lines_per_pod: Max lines per pod (uses config default if None)
            
        Returns:
            List of log entries
        """
        hours = hours_back or (self.config.analysis.max_log_age // 3600)
        max_lines = max_lines_per_pod or self.config.analysis.batch_size
        
        logger.info("Starting log collection", hours_back=hours, max_lines_per_pod=max_lines)
        
        since = datetime.now() - timedelta(hours=hours)
        logs = []
        
        async for entry in self.log_collector.collect_all_logs(
            since=since, 
            max_lines_per_pod=max_lines
        ):
            logs.append(entry)
        
        logger.info("Completed log collection", total_logs=len(logs))
        return logs
    
    async def analyze_logs(self, 
                          logs: List[LogEntry],
                          analysis_types: Optional[List[AnalysisType]] = None) -> List[AnalysisResult]:
        """
        Analyze logs using Claude AI
        
        Args:
            logs: Log entries to analyze
            analysis_types: Types of analysis to perform (uses config if None)
            
        Returns:
            List of analysis results
        """
        if not logs:
            logger.warning("No logs to analyze")
            return []
        
        types_to_run = analysis_types or self.get_enabled_analysis_types()
        
        if not types_to_run:
            logger.warning("No analysis types enabled")
            return []
        
        logger.info("Starting log analysis", 
                   log_count=len(logs),
                   analysis_types=[t.value for t in types_to_run])
        
        # Limit logs to prevent API limits
        logs_to_analyze = logs[:self.config.analysis.batch_size]
        
        results = await self.analyzer.analyze_logs(logs_to_analyze, types_to_run)
        
        logger.info("Completed log analysis", results_count=len(results))
        return results
    
    async def run_single_analysis(self) -> Dict[str, Any]:
        """
        Run a single analysis cycle
        
        Returns:
            Dictionary with analysis results and metadata
        """
        start_time = datetime.now()
        
        try:
            # Collect logs
            logs = await self.collect_logs()
            
            if not logs:
                logger.info("No logs collected, skipping analysis")
                return {
                    'timestamp': start_time.isoformat(),
                    'status': 'no_logs',
                    'logs_collected': 0,
                    'analysis_results': [],
                    'duration_seconds': (datetime.now() - start_time).total_seconds()
                }
            
            # Analyze logs
            results = await self.analyze_logs(logs)
            
            self.last_analysis_time = datetime.now()
            
            analysis_data = {
                'timestamp': start_time.isoformat(),
                'status': 'success',
                'logs_collected': len(logs),
                'analysis_results': [result.to_dict() for result in results],
                'duration_seconds': (datetime.now() - start_time).total_seconds()
            }
            
            logger.info("Single analysis cycle completed",
                       logs_analyzed=len(logs),
                       results_generated=len(results),
                       duration=analysis_data['duration_seconds'])
            
            return analysis_data
            
        except Exception as e:
            logger.error("Analysis cycle failed", error=str(e))
            return {
                'timestamp': start_time.isoformat(),
                'status': 'error',
                'error': str(e),
                'logs_collected': 0,
                'analysis_results': [],
                'duration_seconds': (datetime.now() - start_time).total_seconds()
            }
    
    async def run_continuous_analysis(self):
        """Run continuous analysis loop"""
        self.running = True
        logger.info("Starting continuous analysis loop", 
                   interval=self.config.analysis.analysis_interval)
        
        while self.running:
            try:
                # Run analysis cycle
                analysis_data = await self.run_single_analysis()
                
                # Process results (this would trigger alerts, save to files, etc.)
                await self._process_analysis_results(analysis_data)
                
                # Wait for next interval
                if self.running:  # Check if we should still be running
                    await asyncio.sleep(self.config.analysis.analysis_interval)
                
            except asyncio.CancelledError:
                logger.info("Analysis loop cancelled")
                break
            except Exception as e:
                logger.error("Unexpected error in analysis loop", error=str(e))
                if self.running:
                    # Wait a bit before retrying to avoid tight error loops
                    await asyncio.sleep(min(30, self.config.analysis.analysis_interval))
        
        logger.info("Continuous analysis loop stopped")
    
    def stop_continuous_analysis(self):
        """Stop the continuous analysis loop"""
        self.running = False
        logger.info("Stopping continuous analysis loop")
    
    async def _process_analysis_results(self, analysis_data: Dict[str, Any]):
        """
        Process analysis results (alerts, logging, storage, etc.)
        This is a hook for the reporting system
        """
        # This will be handled by the reporting module
        logger.debug("Processing analysis results", 
                    status=analysis_data['status'],
                    results_count=len(analysis_data.get('analysis_results', [])))
    
    async def get_cluster_health_summary(self) -> Dict[str, Any]:
        """Get a quick health summary of the cluster"""
        try:
            # Collect recent logs (last 30 minutes)
            recent_logs = await collect_recent_logs(
                self.log_collector, 
                hours=0.5,  # 30 minutes
                max_lines_per_pod=50
            )
            
            # Get error logs specifically
            error_logs = [log for log in recent_logs if log.level == 'ERROR']
            
            # Quick analysis on errors if any
            error_analysis = None
            if error_logs:
                results = await self.analyzer.analyze_logs(
                    error_logs[:20],  # Limit for quick analysis
                    [AnalysisType.ERROR_DETECTION, AnalysisType.NATURAL_LANGUAGE_SUMMARY]
                )
                error_analysis = results
            
            # Basic statistics
            namespaces = set(log.namespace for log in recent_logs)
            pods = set(f"{log.namespace}/{log.pod_name}" for log in recent_logs)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'time_range_minutes': 30,
                'total_logs': len(recent_logs),
                'error_logs': len(error_logs),
                'namespaces_active': len(namespaces),
                'pods_active': len(pods),
                'error_analysis': [r.to_dict() for r in error_analysis] if error_analysis else None,
                'status': 'healthy' if len(error_logs) < self.config.alerts.error_threshold else 'issues_detected'
            }
            
        except Exception as e:
            logger.error("Failed to get cluster health summary", error=str(e))
            return {
                'timestamp': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e)
            }


# Convenience functions for common operations

async def quick_cluster_check(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Perform a quick cluster health check"""
    config = load_config(config_path)
    engine = K8sAIAnalysisEngine(config)
    
    # Test connections first
    connections = await engine.test_connections()
    if not all(connections.values()):
        return {
            'status': 'connection_failed',
            'connections': connections,
            'timestamp': datetime.now().isoformat()
        }
    
    # Get health summary
    health = await engine.get_cluster_health_summary()
    health['connections'] = connections
    
    return health


async def run_one_shot_analysis(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Run a single comprehensive analysis"""
    config = load_config(config_path)
    engine = K8sAIAnalysisEngine(config)
    
    # Test connections
    connections = await engine.test_connections()
    if not all(connections.values()):
        return {
            'status': 'connection_failed',
            'connections': connections,
            'timestamp': datetime.now().isoformat()
        }
    
    # Run full analysis
    return await engine.run_single_analysis()


if __name__ == "__main__":
    # Example usage
    async def main():
        # Quick health check
        health = await quick_cluster_check()
        print(f"Cluster health: {health['status']}")
        
        # One-shot analysis
        analysis = await run_one_shot_analysis()
        print(f"Analysis status: {analysis['status']}")
        print(f"Logs analyzed: {analysis['logs_collected']}")
    
    # Uncomment to run example
    # asyncio.run(main())