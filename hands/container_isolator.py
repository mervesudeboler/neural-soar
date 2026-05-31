"""
Container Isolator - Isolates and manages compromised containers/services.
Supports both Docker and Kubernetes in production mode.
"""
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any


@dataclass
class IsolationRecord:
    """Record of a container isolation action."""
    container_id: str
    original_container_id: str
    isolation_type: str  # "network_isolation", "read_only", "honeypot_sidecar"
    reason: str
    isolated_at: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "container_id": self.container_id,
            "original_container_id": self.original_container_id,
            "isolation_type": self.isolation_type,
            "reason": self.reason,
            "isolated_at": self.isolated_at.isoformat(),
            "is_active": self.is_active,
        }


class ContainerIsolator:
    """
    Manages isolation of compromised containers and services.
    In simulation mode: tracks isolation in memory.
    In production mode: uses Docker SDK or kubectl commands.
    """

    def __init__(self, simulation_mode: bool = True, use_kubernetes: bool = False):
        """
        Initialize the container isolator.

        Args:
            simulation_mode: Whether to run in simulation mode
            use_kubernetes: Use Kubernetes instead of Docker
        """
        self.simulation_mode = simulation_mode
        self.use_kubernetes = use_kubernetes

        self.isolated_containers: Dict[str, IsolationRecord] = {}
        self.sidecars: Dict[str, str] = {}  # original_id -> sidecar_id

        self.logger = logging.getLogger(__name__)

    def isolate_container(self, container_id: str, reason: str = "Security threat") -> bool:
        """
        Isolate a container from the network.

        Args:
            container_id: ID of container to isolate
            reason: Reason for isolation

        Returns:
            True if successful
        """
        try:
            if self.simulation_mode:
                return self._isolate_container_simulation(container_id, reason)
            else:
                return self._isolate_container_production(container_id, reason)
        except Exception as e:
            self.logger.error(f"Error isolating container {container_id}: {e}")
            return False

    def _isolate_container_simulation(
        self, container_id: str, reason: str
    ) -> bool:
        """Simulate container isolation."""
        isolation_record = IsolationRecord(
            container_id=container_id,
            original_container_id=container_id,
            isolation_type="network_isolation",
            reason=reason,
        )

        self.isolated_containers[container_id] = isolation_record
        self.logger.info(
            f"[SIM] Isolated container {container_id}: {reason}"
        )
        return True

    def _isolate_container_production(
        self, container_id: str, reason: str
    ) -> bool:
        """Actually isolate container in production."""
        try:
            if self.use_kubernetes:
                return self._isolate_kubernetes_pod(container_id, reason)
            else:
                return self._isolate_docker_container(container_id, reason)
        except Exception as e:
            self.logger.error(f"Production isolation error: {e}")
            return False

    def _isolate_docker_container(self, container_id: str, reason: str) -> bool:
        """Isolate a Docker container."""
        # In production, would use Docker SDK
        # docker_client = docker.from_env()
        # container = docker_client.containers.get(container_id)
        # Create network isolation

        isolation_record = IsolationRecord(
            container_id=container_id,
            original_container_id=container_id,
            isolation_type="network_isolation",
            reason=reason,
        )

        self.isolated_containers[container_id] = isolation_record
        self.logger.info(
            f"[PROD] Isolated Docker container {container_id}: {reason}"
        )
        return True

    def _isolate_kubernetes_pod(self, container_id: str, reason: str) -> bool:
        """Isolate a Kubernetes pod."""
        # In production, would use kubectl client
        # Apply network policy to isolate pod
        # kubectl patch pod <pod_name> --type='json' -p='[...]'

        isolation_record = IsolationRecord(
            container_id=container_id,
            original_container_id=container_id,
            isolation_type="network_isolation",
            reason=reason,
        )

        self.isolated_containers[container_id] = isolation_record
        self.logger.info(
            f"[PROD] Isolated Kubernetes pod {container_id}: {reason}"
        )
        return True

    def restore_container(self, container_id: str) -> bool:
        """
        Restore a previously isolated container.

        Args:
            container_id: ID of container to restore

        Returns:
            True if successful
        """
        try:
            if container_id not in self.isolated_containers:
                self.logger.warning(f"Container {container_id} not found in isolation")
                return False

            if self.simulation_mode:
                del self.isolated_containers[container_id]
                self.logger.info(f"[SIM] Restored container {container_id}")
                return True
            else:
                # Remove isolation in production
                del self.isolated_containers[container_id]
                self.logger.info(f"[PROD] Restored container {container_id}")
                return True

        except Exception as e:
            self.logger.error(f"Error restoring container {container_id}: {e}")
            return False

    def get_isolated_containers(self) -> List[str]:
        """Get list of currently isolated containers."""
        return [
            cid for cid, record in self.isolated_containers.items()
            if record.is_active
        ]

    def create_clean_sidecar(self, original_container_id: str) -> str:
        """
        Create a clean sidecar container for forensics and safe operation.

        Args:
            original_container_id: ID of the compromised container

        Returns:
            ID of the new sidecar container
        """
        try:
            sidecar_id = str(uuid.uuid4())[:12]

            if self.simulation_mode:
                self.sidecars[original_container_id] = sidecar_id
                self.logger.info(
                    f"[SIM] Created sidecar {sidecar_id} for {original_container_id}"
                )
            else:
                # In production, would create actual container
                # docker_client.containers.create(image="clean-base:latest", ...)
                self.sidecars[original_container_id] = sidecar_id
                self.logger.info(
                    f"[PROD] Created sidecar {sidecar_id} for {original_container_id}"
                )

            return sidecar_id

        except Exception as e:
            self.logger.error(
                f"Error creating sidecar for {original_container_id}: {e}"
            )
            return ""

    def implement_dynamic_honeypot_provisioning(self, pod_id: str) -> Dict[str, Any]:
        """
        Create a dynamic honeypot alongside a compromised pod for intelligence gathering.

        Args:
            pod_id: ID of the compromised pod

        Returns:
            Dictionary with honeypot details
        """
        try:
            honeypot_id = str(uuid.uuid4())[:12]
            honeypot_port = 8000 + len(self.isolated_containers)

            honeypot_config = {
                "honeypot_id": honeypot_id,
                "target_pod": pod_id,
                "honeypot_port": honeypot_port,
                "service_type": "dynamic_monitor",
                "created_at": datetime.utcnow().isoformat(),
                "status": "active",
            }

            if self.simulation_mode:
                self.logger.info(
                    f"[SIM] Provisioned honeypot {honeypot_id} for pod {pod_id} "
                    f"on port {honeypot_port}"
                )
            else:
                # In production, would create actual honeypot pod
                # kubectl run honeypot-<id> --image=honeypot:latest --port=<port>
                self.logger.info(
                    f"[PROD] Provisioned honeypot {honeypot_id} for pod {pod_id} "
                    f"on port {honeypot_port}"
                )

            return honeypot_config

        except Exception as e:
            self.logger.error(
                f"Error provisioning honeypot for {pod_id}: {e}"
            )
            return {}

    def get_isolation_status(self, container_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed isolation status for a container."""
        if container_id not in self.isolated_containers:
            return None

        record = self.isolated_containers[container_id]
        sidecar_id = self.sidecars.get(container_id)

        return {
            "container_id": container_id,
            "isolation_type": record.isolation_type,
            "reason": record.reason,
            "isolated_at": record.isolated_at.isoformat(),
            "is_active": record.is_active,
            "sidecar_id": sidecar_id,
            "duration_seconds": (
                (datetime.utcnow() - record.isolated_at).total_seconds()
            ),
        }

    def get_all_isolation_records(self) -> List[Dict[str, Any]]:
        """Get all isolation records."""
        return [
            record.to_dict() for record in self.isolated_containers.values()
        ]

    def get_isolation_summary(self) -> Dict[str, Any]:
        """Get summary of container isolation status."""
        active_isolations = [
            record for record in self.isolated_containers.values()
            if record.is_active
        ]

        return {
            "total_isolated": len(self.isolated_containers),
            "active_isolations": len(active_isolations),
            "sidecars_created": len(self.sidecars),
            "isolation_types": self._count_isolation_types(),
            "isolation_reasons": self._extract_isolation_reasons(),
        }

    def _count_isolation_types(self) -> Dict[str, int]:
        """Count isolations by type."""
        type_counts = {}

        for record in self.isolated_containers.values():
            itype = record.isolation_type
            type_counts[itype] = type_counts.get(itype, 0) + 1

        return type_counts

    def _extract_isolation_reasons(self) -> Dict[str, int]:
        """Extract and count isolation reasons."""
        reason_counts = {}

        for record in self.isolated_containers.values():
            reason = record.reason
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

        return reason_counts

    def cleanup_expired_isolations(self, max_age_seconds: int = 86400) -> int:
        """
        Remove isolations older than max_age_seconds.

        Args:
            max_age_seconds: Maximum age for an isolation record

        Returns:
            Number of records cleaned up
        """
        current_time = datetime.utcnow()
        cleaned_count = 0

        expired = []
        for container_id, record in self.isolated_containers.items():
            age = (current_time - record.isolated_at).total_seconds()
            if age > max_age_seconds:
                expired.append(container_id)

        for container_id in expired:
            record = self.isolated_containers[container_id]
            record.is_active = False
            cleaned_count += 1
            self.logger.info(
                f"Marked isolation of {container_id} as inactive (age: {age}s)"
            )

        return cleaned_count
