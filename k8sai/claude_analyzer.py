"""
Claude AI integration for intelligent log analysis
Provides natural language interpretation, error detection, and troubleshooting suggestions
"""

import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import json
import structlog
from anthropic import AsyncAnthropic

from .log_collector import LogEntry

logger = structlog.get_logger(__name__)


class AnalysisType(Enum):
    """Types of analysis that can be performed"""
    ERROR_DETECTION = "error_detection"
    PERFORMANCE_ANALYSIS = "performance_analysis"
    SECURITY_ANALYSIS = "security_analysis"
    RESOURCE_ANALYSIS = "resource_analysis"
    NATURAL_LANGUAGE_SUMMARY = "natural_language_summary"
    TROUBLESHOOTING_SUGGESTIONS = "troubleshooting_suggestions"


@dataclass
class AnalysisResult:
    """Result of AI analysis on log entries"""
    
    analysis_type: AnalysisType
    timestamp: str
    summary: str
    findings: List[Dict[str, Any]]
    confidence: float
    suggestions: List[str]
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary"""
        return {
            'analysis_type': self.analysis_type.value,
            'timestamp': self.timestamp,
            'summary': self.summary,
            'findings': self.findings,
            'confidence': self.confidence,
            'suggestions': self.suggestions,
            'metadata': self.metadata
        }


class ClaudeAnalyzer:
    """Claude AI-powered log analyzer"""
    
    def __init__(self, 
                 api_key: str,
                 model: str = "claude-3-5-sonnet-20241022",
                 max_tokens: int = 4096,
                 temperature: float = 0.1):
        """
        Initialize Claude analyzer
        
        Args:
            api_key: Anthropic API key
            model: Claude model to use
            max_tokens: Maximum tokens per request
            temperature: Model temperature (0.0 = deterministic, 1.0 = creative)
        """
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        
        logger.info("Initialized Claude analyzer", model=model, max_tokens=max_tokens)
    
    async def _make_claude_request(self, 
                                 system_prompt: str, 
                                 user_prompt: str) -> str:
        """Make request to Claude API"""
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            return response.content[0].text
            
        except Exception as e:
            logger.error("Claude API request failed", error=str(e))
            raise
    
    def _format_logs_for_analysis(self, logs: List[LogEntry], max_logs: int = 50) -> str:
        """Format log entries for Claude analysis"""
        # Limit number of logs to prevent token overflow
        logs_to_analyze = logs[:max_logs]
        
        formatted_logs = []
        for i, log in enumerate(logs_to_analyze, 1):
            formatted_log = (
                f"Log {i}:\n"
                f"  Timestamp: {log.timestamp.isoformat()}\n"
                f"  Namespace: {log.namespace}\n"
                f"  Pod: {log.pod_name}\n"
                f"  Container: {log.container_name}\n"
                f"  Level: {log.level}\n"
                f"  Message: {log.message}\n"
                f"  Labels: {json.dumps(log.labels)}\n"
            )
            formatted_logs.append(formatted_log)
        
        return "\n".join(formatted_logs)
    
    async def detect_errors(self, logs: List[LogEntry]) -> AnalysisResult:
        """Detect and classify errors in log entries"""
        
        system_prompt = """You are an expert Kubernetes administrator and DevOps engineer analyzing application logs. Your task is to identify, classify, and provide insights about errors found in the logs.

Focus on:
1. Error classification (application errors, infrastructure errors, configuration errors, etc.)
2. Error severity assessment
3. Potential root causes
4. Impact assessment
5. Patterns or correlations between errors

Provide your response in JSON format with the following structure:
{
  "summary": "Brief summary of error analysis",
  "findings": [
    {
      "error_type": "classification of error",
      "severity": "low|medium|high|critical",
      "description": "detailed description",
      "affected_components": ["list", "of", "components"],
      "potential_causes": ["list", "of", "causes"],
      "log_references": ["log numbers that contain this error"]
    }
  ],
  "confidence": 0.85,
  "suggestions": ["actionable troubleshooting steps"]
}"""
        
        logs_text = self._format_logs_for_analysis(logs)
        user_prompt = f"Analyze the following Kubernetes logs for errors:\n\n{logs_text}"
        
        try:
            response = await self._make_claude_request(system_prompt, user_prompt)
            
            # Parse JSON response
            result_data = json.loads(response)
            
            return AnalysisResult(
                analysis_type=AnalysisType.ERROR_DETECTION,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary=result_data.get('summary', ''),
                findings=result_data.get('findings', []),
                confidence=result_data.get('confidence', 0.0),
                suggestions=result_data.get('suggestions', []),
                metadata={'logs_analyzed': len(logs)}
            )
            
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Claude response as JSON", error=str(e))
            # Fallback with basic analysis
            return AnalysisResult(
                analysis_type=AnalysisType.ERROR_DETECTION,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary="Error analysis failed due to response parsing issues",
                findings=[],
                confidence=0.0,
                suggestions=["Review logs manually for error patterns"]
            )
    
    async def analyze_performance(self, logs: List[LogEntry]) -> AnalysisResult:
        """Analyze performance-related issues in logs"""
        
        system_prompt = """You are an expert performance analyst for Kubernetes applications. Analyze the provided logs for performance issues, bottlenecks, and optimization opportunities.

Focus on:
1. Response time issues
2. Resource constraints (CPU, memory, disk, network)
3. Timeout errors
4. Queue/backlog issues
5. Performance degradation patterns
6. Scalability concerns

Provide your response in JSON format with the following structure:
{
  "summary": "Brief summary of performance analysis",
  "findings": [
    {
      "issue_type": "type of performance issue",
      "severity": "low|medium|high|critical",
      "description": "detailed description",
      "affected_resources": ["list", "of", "resources"],
      "metrics": {"key": "value"},
      "log_references": ["log numbers showing this issue"]
    }
  ],
  "confidence": 0.85,
  "suggestions": ["performance optimization recommendations"]
}"""
        
        logs_text = self._format_logs_for_analysis(logs)
        user_prompt = f"Analyze the following Kubernetes logs for performance issues:\n\n{logs_text}"
        
        try:
            response = await self._make_claude_request(system_prompt, user_prompt)
            result_data = json.loads(response)
            
            return AnalysisResult(
                analysis_type=AnalysisType.PERFORMANCE_ANALYSIS,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary=result_data.get('summary', ''),
                findings=result_data.get('findings', []),
                confidence=result_data.get('confidence', 0.0),
                suggestions=result_data.get('suggestions', []),
                metadata={'logs_analyzed': len(logs)}
            )
            
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Claude response for performance analysis", error=str(e))
            return AnalysisResult(
                analysis_type=AnalysisType.PERFORMANCE_ANALYSIS,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary="Performance analysis failed due to response parsing issues",
                findings=[],
                confidence=0.0,
                suggestions=["Review logs manually for performance patterns"]
            )
    
    async def analyze_security(self, logs: List[LogEntry]) -> AnalysisResult:
        """Analyze security-related concerns in logs"""
        
        system_prompt = """You are a cybersecurity expert analyzing Kubernetes application logs for security threats and vulnerabilities. 

Focus on:
1. Authentication and authorization failures
2. Suspicious access patterns
3. Potential security breaches
4. Malicious activity indicators
5. Compliance violations
6. Configuration security issues

Provide your response in JSON format with the following structure:
{
  "summary": "Brief summary of security analysis",
  "findings": [
    {
      "threat_type": "type of security threat",
      "severity": "low|medium|high|critical",
      "description": "detailed description",
      "indicators": ["list", "of", "indicators"],
      "potential_impact": "description of impact",
      "log_references": ["log numbers showing this threat"]
    }
  ],
  "confidence": 0.85,
  "suggestions": ["security remediation steps"]
}"""
        
        logs_text = self._format_logs_for_analysis(logs)
        user_prompt = f"Analyze the following Kubernetes logs for security threats:\n\n{logs_text}"
        
        try:
            response = await self._make_claude_request(system_prompt, user_prompt)
            result_data = json.loads(response)
            
            return AnalysisResult(
                analysis_type=AnalysisType.SECURITY_ANALYSIS,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary=result_data.get('summary', ''),
                findings=result_data.get('findings', []),
                confidence=result_data.get('confidence', 0.0),
                suggestions=result_data.get('suggestions', []),
                metadata={'logs_analyzed': len(logs)}
            )
            
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Claude response for security analysis", error=str(e))
            return AnalysisResult(
                analysis_type=AnalysisType.SECURITY_ANALYSIS,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary="Security analysis failed due to response parsing issues",
                findings=[],
                confidence=0.0,
                suggestions=["Review logs manually for security indicators"]
            )
    
    async def analyze_resource_usage(self, logs: List[LogEntry]) -> AnalysisResult:
        """Analyze resource usage patterns in logs"""
        
        system_prompt = """You are a Kubernetes resource optimization expert. Analyze the provided logs for resource usage patterns, efficiency opportunities, and scaling recommendations.

Focus on:
1. Resource utilization patterns
2. Memory and CPU usage indicators
3. Storage and network usage
4. Scaling events and patterns
5. Resource waste identification
6. Optimization opportunities

Provide your response in JSON format with the following structure:
{
  "summary": "Brief summary of resource analysis",
  "findings": [
    {
      "resource_type": "cpu|memory|storage|network|pods",
      "usage_pattern": "description of usage pattern",
      "efficiency": "low|medium|high",
      "recommendations": ["optimization recommendations"],
      "log_references": ["log numbers showing this pattern"]
    }
  ],
  "confidence": 0.85,
  "suggestions": ["resource optimization steps"]
}"""
        
        logs_text = self._format_logs_for_analysis(logs)
        user_prompt = f"Analyze the following Kubernetes logs for resource usage patterns:\n\n{logs_text}"
        
        try:
            response = await self._make_claude_request(system_prompt, user_prompt)
            result_data = json.loads(response)
            
            return AnalysisResult(
                analysis_type=AnalysisType.RESOURCE_ANALYSIS,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary=result_data.get('summary', ''),
                findings=result_data.get('findings', []),
                confidence=result_data.get('confidence', 0.0),
                suggestions=result_data.get('suggestions', []),
                metadata={'logs_analyzed': len(logs)}
            )
            
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Claude response for resource analysis", error=str(e))
            return AnalysisResult(
                analysis_type=AnalysisType.RESOURCE_ANALYSIS,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary="Resource analysis failed due to response parsing issues",
                findings=[],
                confidence=0.0,
                suggestions=["Review logs manually for resource patterns"]
            )
    
    async def generate_natural_language_summary(self, logs: List[LogEntry]) -> AnalysisResult:
        """Generate human-readable summary of what's happening in the logs"""
        
        system_prompt = """You are an expert Kubernetes administrator who excels at explaining complex technical logs in clear, human-readable language. 

Create a natural language summary that explains:
1. What applications/services are running
2. Overall system health and status
3. Key events and activities
4. Any notable patterns or trends
5. General operational insights

Make your explanation accessible to both technical and non-technical stakeholders. Use clear, concise language and avoid excessive jargon.

Provide your response in JSON format:
{
  "summary": "Comprehensive natural language summary of log activities",
  "findings": [
    {
      "category": "application|infrastructure|events|patterns",
      "description": "human-readable description",
      "significance": "why this is important",
      "log_references": ["relevant log numbers"]
    }
  ],
  "confidence": 0.85,
  "suggestions": ["high-level operational recommendations"]
}"""
        
        logs_text = self._format_logs_for_analysis(logs)
        user_prompt = f"Create a natural language summary of what's happening in these Kubernetes logs:\n\n{logs_text}"
        
        try:
            response = await self._make_claude_request(system_prompt, user_prompt)
            result_data = json.loads(response)
            
            return AnalysisResult(
                analysis_type=AnalysisType.NATURAL_LANGUAGE_SUMMARY,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary=result_data.get('summary', ''),
                findings=result_data.get('findings', []),
                confidence=result_data.get('confidence', 0.0),
                suggestions=result_data.get('suggestions', []),
                metadata={'logs_analyzed': len(logs)}
            )
            
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Claude response for natural language summary", error=str(e))
            return AnalysisResult(
                analysis_type=AnalysisType.NATURAL_LANGUAGE_SUMMARY,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary="Summary generation failed due to response parsing issues",
                findings=[],
                confidence=0.0,
                suggestions=["Review logs manually for operational insights"]
            )
    
    async def generate_troubleshooting_suggestions(self, logs: List[LogEntry]) -> AnalysisResult:
        """Generate specific troubleshooting suggestions based on log analysis"""
        
        system_prompt = """You are an expert Kubernetes troubleshooter. Based on the provided logs, generate specific, actionable troubleshooting steps and recommendations.

Focus on:
1. Immediate actions to resolve issues
2. Investigation steps to gather more information
3. Prevention measures for future issues
4. Best practices for system health
5. Monitoring recommendations

Provide practical, step-by-step guidance that can be followed by operations teams.

Provide your response in JSON format:
{
  "summary": "Overview of recommended troubleshooting approach",
  "findings": [
    {
      "issue": "specific issue identified",
      "priority": "low|medium|high|urgent",
      "immediate_actions": ["immediate steps to take"],
      "investigation_steps": ["steps to investigate further"],
      "prevention_measures": ["steps to prevent recurrence"],
      "log_references": ["relevant log numbers"]
    }
  ],
  "confidence": 0.85,
  "suggestions": ["general troubleshooting recommendations"]
}"""
        
        logs_text = self._format_logs_for_analysis(logs)
        user_prompt = f"Generate troubleshooting suggestions for these Kubernetes logs:\n\n{logs_text}"
        
        try:
            response = await self._make_claude_request(system_prompt, user_prompt)
            result_data = json.loads(response)
            
            return AnalysisResult(
                analysis_type=AnalysisType.TROUBLESHOOTING_SUGGESTIONS,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary=result_data.get('summary', ''),
                findings=result_data.get('findings', []),
                confidence=result_data.get('confidence', 0.0),
                suggestions=result_data.get('suggestions', []),
                metadata={'logs_analyzed': len(logs)}
            )
            
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Claude response for troubleshooting suggestions", error=str(e))
            return AnalysisResult(
                analysis_type=AnalysisType.TROUBLESHOOTING_SUGGESTIONS,
                timestamp=logs[0].timestamp.isoformat() if logs else "",
                summary="Troubleshooting suggestion generation failed",
                findings=[],
                confidence=0.0,
                suggestions=["Review logs manually and consult documentation"]
            )
    
    async def analyze_logs(self, 
                          logs: List[LogEntry], 
                          analysis_types: List[AnalysisType]) -> List[AnalysisResult]:
        """
        Perform multiple types of analysis on log entries
        
        Args:
            logs: List of log entries to analyze
            analysis_types: List of analysis types to perform
            
        Returns:
            List of analysis results
        """
        if not logs:
            logger.warning("No logs provided for analysis")
            return []
        
        results = []
        
        logger.info("Starting log analysis", 
                   log_count=len(logs), 
                   analysis_types=[t.value for t in analysis_types])
        
        # Run analyses in parallel for efficiency
        tasks = []
        
        for analysis_type in analysis_types:
            if analysis_type == AnalysisType.ERROR_DETECTION:
                tasks.append(self.detect_errors(logs))
            elif analysis_type == AnalysisType.PERFORMANCE_ANALYSIS:
                tasks.append(self.analyze_performance(logs))
            elif analysis_type == AnalysisType.SECURITY_ANALYSIS:
                tasks.append(self.analyze_security(logs))
            elif analysis_type == AnalysisType.RESOURCE_ANALYSIS:
                tasks.append(self.analyze_resource_usage(logs))
            elif analysis_type == AnalysisType.NATURAL_LANGUAGE_SUMMARY:
                tasks.append(self.generate_natural_language_summary(logs))
            elif analysis_type == AnalysisType.TROUBLESHOOTING_SUGGESTIONS:
                tasks.append(self.generate_troubleshooting_suggestions(logs))
        
        # Execute all analyses concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and log errors
            valid_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error("Analysis failed", 
                               analysis_type=analysis_types[i].value, 
                               error=str(result))
                else:
                    valid_results.append(result)
            
            results = valid_results
        
        logger.info("Completed log analysis", results_count=len(results))
        return results


# Convenience functions for common analysis workflows

async def quick_error_analysis(analyzer: ClaudeAnalyzer, logs: List[LogEntry]) -> AnalysisResult:
    """Perform quick error detection analysis"""
    results = await analyzer.analyze_logs(logs, [AnalysisType.ERROR_DETECTION])
    return results[0] if results else AnalysisResult(
        analysis_type=AnalysisType.ERROR_DETECTION,
        timestamp="",
        summary="No analysis results",
        findings=[],
        confidence=0.0,
        suggestions=[]
    )


async def comprehensive_analysis(analyzer: ClaudeAnalyzer, logs: List[LogEntry]) -> List[AnalysisResult]:
    """Perform comprehensive analysis with all available analysis types"""
    return await analyzer.analyze_logs(logs, list(AnalysisType))


if __name__ == "__main__":
    # Example usage
    async def main():
        # This would typically be loaded from config
        analyzer = ClaudeAnalyzer(api_key="your-api-key")
        
        # Example log entries (would come from log collector)
        sample_logs = [
            LogEntry(
                timestamp=datetime.now(),
                namespace="production",
                pod_name="web-app-123",
                container_name="app",
                message="ERROR: Database connection failed",
                level="ERROR"
            )
        ]
        
        # Perform error analysis
        result = await quick_error_analysis(analyzer, sample_logs)
        print(f"Analysis: {result.summary}")
    
    # Uncomment to run example
    # asyncio.run(main())