"""
Basic tests for K8s AI Log Analyzer
"""

import pytest
from datetime import datetime
import tempfile
import os
from pathlib import Path

from k8sai.config import load_config, save_example_config, AppConfig
from k8sai.log_collector import LogEntry, KubectlLogCollector
from k8sai.claude_analyzer import ClaudeAnalyzer, AnalysisType


class TestConfiguration:
    """Test configuration management"""
    
    def test_default_config_creation(self):
        """Test creating default configuration"""
        config = AppConfig()
        assert config.debug is False
        assert config.log_level == "INFO"
        assert config.cluster.name == "default"
    
    def test_example_config_generation(self):
        """Test generating example configuration file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.yaml"
            save_example_config(str(config_path))
            
            assert config_path.exists()
            
            # Load the generated config
            loaded_config = load_config(str(config_path))
            assert loaded_config.cluster.name == "my-aks-cluster"


class TestLogEntry:
    """Test log entry functionality"""
    
    def test_log_entry_creation(self):
        """Test creating a log entry"""
        entry = LogEntry(
            timestamp=datetime.now(),
            namespace="test-ns",
            pod_name="test-pod",
            container_name="test-container",
            message="Test message",
            level="INFO"
        )
        
        assert entry.namespace == "test-ns"
        assert entry.pod_name == "test-pod"
        assert entry.message == "Test message"
        assert entry.level == "INFO"
    
    def test_log_entry_to_dict(self):
        """Test converting log entry to dictionary"""
        entry = LogEntry(
            timestamp=datetime.now(),
            namespace="test-ns",
            pod_name="test-pod",
            container_name="test-container",
            message="Test message"
        )
        
        data = entry.to_dict()
        assert data['namespace'] == "test-ns"
        assert data['pod_name'] == "test-pod"
        assert data['message'] == "Test message"
        assert 'timestamp' in data


class TestKubectlLogCollector:
    """Test kubectl log collector (without actual kubectl calls)"""
    
    def test_collector_initialization(self):
        """Test initializing the collector"""
        collector = KubectlLogCollector(
            namespaces=['default', 'test'],
            exclude_namespaces=['kube-system']
        )
        
        assert collector.namespaces == ['default', 'test']
        assert collector.exclude_namespaces == ['kube-system']
    
    def test_log_level_determination(self):
        """Test log level determination from message"""
        collector = KubectlLogCollector()
        
        assert collector._determine_log_level("ERROR: Something failed") == "ERROR"
        assert collector._determine_log_level("WARN: Warning message") == "WARN"
        assert collector._determine_log_level("DEBUG: Debug info") == "DEBUG"
        assert collector._determine_log_level("Normal info message") == "INFO"


@pytest.mark.asyncio
class TestClaudeAnalyzer:
    """Test Claude analyzer (mocked)"""
    
    @pytest.fixture
    def sample_logs(self):
        """Create sample log entries for testing"""
        return [
            LogEntry(
                timestamp=datetime.now(),
                namespace="production",
                pod_name="web-app-123",
                container_name="app",
                message="ERROR: Database connection failed",
                level="ERROR"
            ),
            LogEntry(
                timestamp=datetime.now(),
                namespace="production",
                pod_name="web-app-123",
                container_name="app",
                message="INFO: Application started successfully",
                level="INFO"
            )
        ]
    
    def test_analyzer_initialization(self):
        """Test initializing Claude analyzer"""
        analyzer = ClaudeAnalyzer(
            api_key="test-key",
            model="claude-3-5-sonnet-20241022"
        )
        
        assert analyzer.model == "claude-3-5-sonnet-20241022"
        assert analyzer.max_tokens == 4096
    
    def test_log_formatting(self, sample_logs):
        """Test formatting logs for analysis"""
        analyzer = ClaudeAnalyzer(api_key="test-key")
        
        formatted = analyzer._format_logs_for_analysis(sample_logs)
        
        assert "Log 1:" in formatted
        assert "production" in formatted
        assert "web-app-123" in formatted
        assert "ERROR: Database connection failed" in formatted


class TestIntegration:
    """Integration tests"""
    
    def test_config_loading_with_env_vars(self):
        """Test loading configuration with environment variables"""
        # Set environment variable
        os.environ['ANTHROPIC_API_KEY'] = 'test-api-key'
        
        try:
            config = load_config()
            assert config.claude.api_key == 'test-api-key'
        finally:
            # Clean up
            if 'ANTHROPIC_API_KEY' in os.environ:
                del os.environ['ANTHROPIC_API_KEY']
    
    def test_analysis_types_enum(self):
        """Test analysis type enumeration"""
        assert AnalysisType.ERROR_DETECTION.value == "error_detection"
        assert AnalysisType.SECURITY_ANALYSIS.value == "security_analysis"
        assert AnalysisType.PERFORMANCE_ANALYSIS.value == "performance_analysis"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])