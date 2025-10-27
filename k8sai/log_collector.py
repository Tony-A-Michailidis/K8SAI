"""
Kubernetes log collection module
Interfaces with kubectl to gather logs from all cluster resources
"""

import asyncio
import subprocess
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, AsyncGenerator, Tuple
from dataclasses import dataclass
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class LogEntry:
    """Represents a single log entry from Kubernetes"""
    
    timestamp: datetime
    namespace: str
    pod_name: str
    container_name: str
    message: str
    level: str = "INFO"  # INFO, WARN, ERROR, DEBUG
    labels: Dict[str, str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.labels is None:
            self.labels = {}
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'namespace': self.namespace,
            'pod_name': self.pod_name,
            'container_name': self.container_name,
            'message': self.message,
            'level': self.level,
            'labels': self.labels,
            'metadata': self.metadata
        }


@dataclass
class PodInfo:
    """Information about a Kubernetes pod"""
    
    name: str
    namespace: str
    containers: List[str]
    labels: Dict[str, str]
    status: str
    node: str
    
    def __post_init__(self):
        if self.labels is None:
            self.labels = {}


class KubectlLogCollector:
    """Collects logs from Kubernetes cluster using kubectl"""
    
    def __init__(self, 
                 kubeconfig_path: Optional[str] = None,
                 context: Optional[str] = None,
                 namespaces: List[str] = None,
                 exclude_namespaces: List[str] = None):
        """
        Initialize the log collector
        
        Args:
            kubeconfig_path: Path to kubeconfig file
            context: Kubernetes context to use
            namespaces: List of namespaces to monitor (if None, monitors all)
            exclude_namespaces: List of namespaces to exclude
        """
        self.kubeconfig_path = kubeconfig_path
        self.context = context
        self.namespaces = namespaces or []
        self.exclude_namespaces = exclude_namespaces or []
        
        logger.info("Initialized kubectl log collector", 
                   kubeconfig=kubeconfig_path, 
                   context=context,
                   namespaces=self.namespaces,
                   exclude_namespaces=self.exclude_namespaces)
    
    def _build_kubectl_cmd(self, cmd_args: List[str]) -> List[str]:
        """Build kubectl command with proper context and kubeconfig"""
        cmd = ['kubectl']
        
        if self.kubeconfig_path:
            cmd.extend(['--kubeconfig', str(self.kubeconfig_path)])
        
        if self.context:
            cmd.extend(['--context', self.context])
        
        cmd.extend(cmd_args)
        return cmd
    
    async def _run_kubectl_command(self, cmd_args: List[str]) -> Tuple[str, str, int]:
        """Run kubectl command asynchronously"""
        cmd = self._build_kubectl_cmd(cmd_args)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = await process.communicate()
            return stdout, stderr, process.returncode
            
        except Exception as e:
            logger.error("Failed to run kubectl command", cmd=cmd, error=str(e))
            return "", str(e), 1
    
    async def get_namespaces(self) -> List[str]:
        """Get list of available namespaces"""
        stdout, stderr, returncode = await self._run_kubectl_command([
            'get', 'namespaces', '-o', 'jsonpath={.items[*].metadata.name}'
        ])
        
        if returncode != 0:
            logger.error("Failed to get namespaces", stderr=stderr)
            return []
        
        all_namespaces = stdout.strip().split()
        
        # Filter namespaces based on configuration
        filtered_namespaces = []
        for ns in all_namespaces:
            if ns in self.exclude_namespaces:
                continue
            
            if not self.namespaces or ns in self.namespaces:
                filtered_namespaces.append(ns)
        
        logger.info("Discovered namespaces", count=len(filtered_namespaces), namespaces=filtered_namespaces)
        return filtered_namespaces
    
    async def get_pods_in_namespace(self, namespace: str) -> List[PodInfo]:
        """Get all pods in a specific namespace"""
        stdout, stderr, returncode = await self._run_kubectl_command([
            'get', 'pods', '-n', namespace, '-o', 'json'
        ])
        
        if returncode != 0:
            logger.error("Failed to get pods in namespace", namespace=namespace, stderr=stderr)
            return []
        
        try:
            data = json.loads(stdout)
            pods = []
            
            for item in data.get('items', []):
                metadata = item.get('metadata', {})
                spec = item.get('spec', {})
                status = item.get('status', {})
                
                # Extract container names
                containers = []
                for container in spec.get('containers', []):
                    containers.append(container.get('name', ''))
                
                pod_info = PodInfo(
                    name=metadata.get('name', ''),
                    namespace=metadata.get('namespace', ''),
                    containers=containers,
                    labels=metadata.get('labels', {}),
                    status=status.get('phase', 'Unknown'),
                    node=spec.get('nodeName', 'Unknown')
                )
                pods.append(pod_info)
            
            logger.debug("Found pods in namespace", namespace=namespace, count=len(pods))
            return pods
            
        except json.JSONDecodeError as e:
            logger.error("Failed to parse pods JSON", namespace=namespace, error=str(e))
            return []
    
    async def get_logs_for_pod(self, 
                              pod_info: PodInfo, 
                              container: str = None,
                              since: datetime = None,
                              tail_lines: int = None) -> List[LogEntry]:
        """Get logs for a specific pod/container"""
        cmd_args = ['logs', '-n', pod_info.namespace, pod_info.name]
        
        if container:
            cmd_args.extend(['-c', container])
        
        if since:
            # kubectl expects relative time like '1h' or '30m'
            time_diff = datetime.now() - since
            if time_diff.total_seconds() > 0:
                hours = int(time_diff.total_seconds() // 3600)
                if hours > 0:
                    cmd_args.extend(['--since', f'{hours}h'])
                else:
                    minutes = int(time_diff.total_seconds() // 60)
                    cmd_args.extend(['--since', f'{minutes}m'])
        
        if tail_lines:
            cmd_args.extend(['--tail', str(tail_lines)])
        
        cmd_args.extend(['--timestamps'])
        
        stdout, stderr, returncode = await self._run_kubectl_command(cmd_args)
        
        if returncode != 0:
            logger.warning("Failed to get logs for pod", 
                         pod=pod_info.name, 
                         container=container, 
                         stderr=stderr)
            return []
        
        return self._parse_log_output(stdout, pod_info, container or pod_info.containers[0] if pod_info.containers else 'unknown')
    
    def _parse_log_output(self, log_output: str, pod_info: PodInfo, container: str) -> List[LogEntry]:
        """Parse kubectl log output into LogEntry objects"""
        entries = []
        
        for line in log_output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                # Parse timestamped log line: "2023-10-27T10:30:00.123456789Z message"
                parts = line.split(' ', 1)
                if len(parts) < 2:
                    continue
                
                timestamp_str = parts[0]
                message = parts[1]
                
                # Parse timestamp
                try:
                    # Remove nanoseconds if present (Python datetime doesn't support them)
                    if '.' in timestamp_str and timestamp_str.endswith('Z'):
                        timestamp_str = timestamp_str.split('.')[0] + 'Z'
                    
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except ValueError:
                    # Fallback to current time if timestamp parsing fails
                    timestamp = datetime.now()
                
                # Determine log level from message content
                level = self._determine_log_level(message)
                
                entry = LogEntry(
                    timestamp=timestamp,
                    namespace=pod_info.namespace,
                    pod_name=pod_info.name,
                    container_name=container,
                    message=message,
                    level=level,
                    labels=pod_info.labels.copy(),
                    metadata={
                        'pod_status': pod_info.status,
                        'node': pod_info.node
                    }
                )
                
                entries.append(entry)
                
            except Exception as e:
                logger.warning("Failed to parse log line", line=line, error=str(e))
                continue
        
        return entries
    
    def _determine_log_level(self, message: str) -> str:
        """Determine log level from message content"""
        message_lower = message.lower()
        
        if any(keyword in message_lower for keyword in ['error', 'failed', 'exception', 'panic', 'fatal']):
            return 'ERROR'
        elif any(keyword in message_lower for keyword in ['warn', 'warning']):
            return 'WARN'
        elif any(keyword in message_lower for keyword in ['debug', 'trace']):
            return 'DEBUG'
        else:
            return 'INFO'
    
    async def collect_all_logs(self, 
                             since: datetime = None,
                             max_lines_per_pod: int = 1000) -> AsyncGenerator[LogEntry, None]:
        """
        Collect logs from all pods in all monitored namespaces
        
        Args:
            since: Only collect logs since this time
            max_lines_per_pod: Maximum number of log lines per pod
            
        Yields:
            LogEntry objects for each log line
        """
        logger.info("Starting log collection", since=since, max_lines=max_lines_per_pod)
        
        namespaces = await self.get_namespaces()
        if not namespaces:
            logger.warning("No namespaces found to monitor")
            return
        
        total_entries = 0
        
        for namespace in namespaces:
            logger.info("Collecting logs from namespace", namespace=namespace)
            
            pods = await self.get_pods_in_namespace(namespace)
            
            for pod_info in pods:
                # Skip pods that are not running
                if pod_info.status not in ['Running', 'Succeeded', 'Failed']:
                    continue
                
                # Get logs for each container in the pod
                for container in pod_info.containers:
                    try:
                        entries = await self.get_logs_for_pod(
                            pod_info, 
                            container, 
                            since=since,
                            tail_lines=max_lines_per_pod
                        )
                        
                        for entry in entries:
                            yield entry
                            total_entries += 1
                            
                    except Exception as e:
                        logger.error("Failed to get logs for container",
                                   pod=pod_info.name,
                                   container=container,
                                   error=str(e))
        
        logger.info("Completed log collection", total_entries=total_entries)
    
    async def test_connection(self) -> bool:
        """Test if kubectl connection is working"""
        try:
            stdout, stderr, returncode = await self._run_kubectl_command(['cluster-info'])
            
            if returncode == 0:
                logger.info("Kubectl connection test successful")
                return True
            else:
                logger.error("Kubectl connection test failed", stderr=stderr)
                return False
                
        except Exception as e:
            logger.error("Kubectl connection test error", error=str(e))
            return False


# Convenience functions for common use cases

async def collect_recent_logs(collector: KubectlLogCollector, 
                            hours: int = 1,
                            max_lines_per_pod: int = 1000) -> List[LogEntry]:
    """Collect logs from the last N hours"""
    since = datetime.now() - timedelta(hours=hours)
    logs = []
    
    async for entry in collector.collect_all_logs(since=since, max_lines_per_pod=max_lines_per_pod):
        logs.append(entry)
    
    return logs


async def collect_error_logs(collector: KubectlLogCollector,
                           hours: int = 1,
                           max_lines_per_pod: int = 1000) -> List[LogEntry]:
    """Collect only error-level logs from the last N hours"""
    since = datetime.now() - timedelta(hours=hours)
    error_logs = []
    
    async for entry in collector.collect_all_logs(since=since, max_lines_per_pod=max_lines_per_pod):
        if entry.level == 'ERROR':
            error_logs.append(entry)
    
    return error_logs


if __name__ == "__main__":
    # Example usage
    async def main():
        collector = KubectlLogCollector()
        
        # Test connection
        if not await collector.test_connection():
            print("Failed to connect to Kubernetes cluster")
            return
        
        # Collect recent logs
        logs = await collect_recent_logs(collector, hours=1)
        print(f"Collected {len(logs)} log entries")
        
        # Display first few entries
        for log in logs[:5]:
            print(f"{log.timestamp} [{log.level}] {log.namespace}/{log.pod_name}: {log.message[:100]}")
    
    asyncio.run(main())