"""
Event Bus - Central event routing and pub/sub system for Neural SOAR.
Handles secure event distribution across system components.
"""

import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from queue import Queue
from typing import Callable, Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class EventBusBase(ABC):
    """Abstract base class for event bus implementations."""

    @abstractmethod
    def publish(self, channel: str, data: Dict[str, Any]) -> None:
        """Publish event data to a channel."""
        pass

    @abstractmethod
    def subscribe(self, channel: str, callback: Callable[[Dict[str, Any]], None]) -> str:
        """Subscribe to events on a channel. Returns subscription ID."""
        pass

    @abstractmethod
    def unsubscribe(self, channel: str, subscription_id: str) -> bool:
        """Unsubscribe from a channel."""
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Shutdown the event bus."""
        pass


class InMemoryEventBus(EventBusBase):
    """
    In-memory implementation of event bus using thread-safe queues.
    Fallback implementation when Redis is not available.
    """

    def __init__(self, max_queue_size: int = 10000):
        """
        Initialize in-memory event bus.

        Args:
            max_queue_size: Maximum number of events in queue before dropping oldest.
        """
        self._channels: Dict[str, List[tuple]] = defaultdict(list)
        self._subscription_lock = threading.RLock()
        self._subscription_counter = 0
        self._queues: Dict[str, Queue] = defaultdict(lambda: Queue(maxsize=max_queue_size))
        self._worker_threads: Dict[str, threading.Thread] = {}
        self._running = True
        logger.info("InMemoryEventBus initialized")

    def publish(self, channel: str, data: Dict[str, Any]) -> None:
        """
        Publish event data to a channel.

        Args:
            channel: Channel name/topic for the event.
            data: Event data dictionary to publish.
        """
        if not self._running:
            logger.warning(f"Cannot publish to channel '{channel}': bus is shutdown")
            return

        event = {
            "channel": channel,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data,
        }

        with self._subscription_lock:
            subscriptions = self._channels.get(channel, [])

        for subscription_id, callback in subscriptions:
            try:
                if not self._queues[subscription_id].full():
                    self._queues[subscription_id].put_nowait(event)
                else:
                    logger.warning(f"Event queue for subscription {subscription_id} is full, dropping oldest event")
                    try:
                        self._queues[subscription_id].get_nowait()
                        self._queues[subscription_id].put_nowait(event)
                    except Exception as e:
                        logger.error(f"Failed to manage queue for subscription {subscription_id}: {e}")
            except Exception as e:
                logger.error(f"Error queuing event for subscription {subscription_id}: {e}")

        logger.debug(f"Event published to channel '{channel}' with {len(subscriptions)} subscribers")

    def subscribe(self, channel: str, callback: Callable[[Dict[str, Any]], None]) -> str:
        """
        Subscribe to events on a channel.

        Args:
            channel: Channel name/topic to subscribe to.
            callback: Callable to execute when event is published.

        Returns:
            Subscription ID for later unsubscription.
        """
        with self._subscription_lock:
            self._subscription_counter += 1
            subscription_id = f"{channel}_{self._subscription_counter}"
            self._channels[channel].append((subscription_id, callback))

            worker_thread = threading.Thread(
                target=self._worker,
                args=(subscription_id, callback),
                daemon=True,
                name=f"EventBus-Worker-{subscription_id}",
            )
            worker_thread.start()
            self._worker_threads[subscription_id] = worker_thread

        logger.info(f"Subscription '{subscription_id}' created for channel '{channel}'")
        return subscription_id

    def _worker(self, subscription_id: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Worker thread that processes queued events for a subscription.

        Args:
            subscription_id: The subscription ID this worker handles.
            callback: The callback to execute for each event.
        """
        while self._running:
            try:
                event = self._queues[subscription_id].get(timeout=1.0)
                try:
                    callback(event["data"])
                except Exception as e:
                    logger.error(f"Error executing callback for subscription {subscription_id}: {e}", exc_info=True)
            except Exception:
                continue

    def unsubscribe(self, channel: str, subscription_id: str) -> bool:
        """
        Unsubscribe from a channel.

        Args:
            channel: Channel name to unsubscribe from.
            subscription_id: The subscription ID to remove.

        Returns:
            True if unsubscribed successfully, False if subscription not found.
        """
        with self._subscription_lock:
            if channel not in self._channels:
                logger.warning(f"Channel '{channel}' not found for unsubscription")
                return False

            original_count = len(self._channels[channel])
            self._channels[channel] = [(sid, cb) for sid, cb in self._channels[channel] if sid != subscription_id]

            if len(self._channels[channel]) < original_count:
                self._queues.pop(subscription_id, None)
                self._worker_threads.pop(subscription_id, None)
                logger.info(f"Unsubscribed '{subscription_id}' from channel '{channel}'")
                return True

        logger.warning(f"Subscription '{subscription_id}' not found for channel '{channel}'")
        return False

    def shutdown(self) -> None:
        """Shutdown the event bus and all worker threads."""
        self._running = False
        for worker_thread in self._worker_threads.values():
            worker_thread.join(timeout=2.0)
        self._channels.clear()
        self._queues.clear()
        logger.info("InMemoryEventBus shutdown complete")


class RedisEventBus(EventBusBase):
    """
    Redis-backed implementation of event bus for production deployments.
    Provides distributed pub/sub across multiple instances.
    """

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        """
        Initialize Redis event bus.

        Args:
            host: Redis server hostname.
            port: Redis server port.
            db: Redis database number.
        """
        try:
            import redis
        except ImportError:
            raise ImportError("redis package required for RedisEventBus. Install with: pip install redis")

        self._redis_client = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self._pubsub = self._redis_client.pubsub()
        self._subscriptions: Dict[str, threading.Thread] = {}
        self._subscription_lock = threading.RLock()
        self._running = True

        try:
            self._redis_client.ping()
            logger.info(f"RedisEventBus connected to {host}:{port}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis at {host}:{port}: {e}")
            raise

    def publish(self, channel: str, data: Dict[str, Any]) -> None:
        """
        Publish event data to a channel via Redis.

        Args:
            channel: Channel name/topic for the event.
            data: Event data dictionary to publish.
        """
        if not self._running:
            logger.warning(f"Cannot publish to channel '{channel}': bus is shutdown")
            return

        try:
            event_payload = json.dumps({
                "timestamp": datetime.utcnow().isoformat(),
                "data": data,
            })
            self._redis_client.publish(channel, event_payload)
            logger.debug(f"Event published to Redis channel '{channel}'")
        except Exception as e:
            logger.error(f"Failed to publish to channel '{channel}': {e}")

    def subscribe(self, channel: str, callback: Callable[[Dict[str, Any]], None]) -> str:
        """
        Subscribe to events on a channel via Redis.

        Args:
            channel: Channel name/topic to subscribe to.
            callback: Callable to execute when event is published.

        Returns:
            Subscription ID.
        """
        subscription_id = f"redis_{channel}_{id(callback)}"

        def subscriber_worker():
            pubsub = self._redis_client.pubsub()
            pubsub.subscribe(channel)

            try:
                for message in pubsub.listen():
                    if not self._running:
                        break
                    if message["type"] == "message":
                        try:
                            payload = json.loads(message["data"])
                            callback(payload["data"])
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to decode event from channel '{channel}': {e}")
                        except Exception as e:
                            logger.error(f"Error executing callback for subscription {subscription_id}: {e}", exc_info=True)
            except Exception as e:
                logger.error(f"Subscriber worker error for {subscription_id}: {e}")
            finally:
                pubsub.close()

        with self._subscription_lock:
            worker_thread = threading.Thread(
                target=subscriber_worker,
                daemon=True,
                name=f"RedisEventBus-Worker-{subscription_id}",
            )
            worker_thread.start()
            self._subscriptions[subscription_id] = worker_thread

        logger.info(f"Subscription '{subscription_id}' created for Redis channel '{channel}'")
        return subscription_id

    def unsubscribe(self, channel: str, subscription_id: str) -> bool:
        """
        Unsubscribe from a channel.

        Args:
            channel: Channel name to unsubscribe from.
            subscription_id: The subscription ID to remove.

        Returns:
            True if unsubscribed successfully, False otherwise.
        """
        with self._subscription_lock:
            if subscription_id in self._subscriptions:
                self._subscriptions.pop(subscription_id, None)
                logger.info(f"Unsubscribed '{subscription_id}' from Redis channel '{channel}'")
                return True

        logger.warning(f"Subscription '{subscription_id}' not found")
        return False

    def shutdown(self) -> None:
        """Shutdown the event bus and close Redis connection."""
        self._running = False
        time.sleep(0.5)
        for worker_thread in self._subscriptions.values():
            worker_thread.join(timeout=2.0)
        self._pubsub.close()
        self._redis_client.close()
        logger.info("RedisEventBus shutdown complete")


class MockEventBus(EventBusBase):
    """
    Mock implementation of event bus for testing and simulation.
    Records all events for inspection and replay.
    """

    def __init__(self):
        """Initialize mock event bus with event recording."""
        self.published_events: List[Dict[str, Any]] = []
        self.subscriptions: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.RLock()
        logger.info("MockEventBus initialized for testing")

    def publish(self, channel: str, data: Dict[str, Any]) -> None:
        """
        Record published event (does not actually transmit).

        Args:
            channel: Channel name/topic for the event.
            data: Event data dictionary to publish.
        """
        with self._lock:
            event = {
                "channel": channel,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data,
            }
            self.published_events.append(event)
            logger.debug(f"MockEventBus recorded event on channel '{channel}'")

            for callback in self.subscriptions.get(channel, []):
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Error executing mock callback: {e}")

    def subscribe(self, channel: str, callback: Callable[[Dict[str, Any]], None]) -> str:
        """
        Register a callback for a channel (mock).

        Args:
            channel: Channel name/topic to subscribe to.
            callback: Callable to execute when event is published.

        Returns:
            Subscription ID.
        """
        subscription_id = f"mock_{channel}_{id(callback)}"
        with self._lock:
            self.subscriptions[channel].append(callback)
        logger.info(f"MockEventBus subscription '{subscription_id}' for channel '{channel}'")
        return subscription_id

    def unsubscribe(self, channel: str, subscription_id: str) -> bool:
        """
        Unsubscribe from a channel (mock).

        Args:
            channel: Channel name to unsubscribe from.
            subscription_id: The subscription ID to remove.

        Returns:
            Always returns True for mock.
        """
        logger.info(f"MockEventBus unsubscription '{subscription_id}' from channel '{channel}'")
        return True

    def get_events_on_channel(self, channel: str) -> List[Dict[str, Any]]:
        """
        Get all recorded events for a specific channel.

        Args:
            channel: Channel name to query.

        Returns:
            List of events published on that channel.
        """
        with self._lock:
            return [e for e in self.published_events if e["channel"] == channel]

    def clear_events(self) -> None:
        """Clear all recorded events."""
        with self._lock:
            self.published_events.clear()
        logger.debug("MockEventBus cleared all recorded events")

    def shutdown(self) -> None:
        """Shutdown mock event bus."""
        self.published_events.clear()
        self.subscriptions.clear()
        logger.info("MockEventBus shutdown complete")


class EventBus:
    """
    Factory class for event bus selection with automatic fallback.
    Provides consistent interface regardless of backend.
    """

    _instance: Optional[EventBusBase] = None
    _lock = threading.Lock()

    @classmethod
    def initialize(cls, use_redis: bool = True, **kwargs) -> EventBusBase:
        """
        Initialize the event bus with automatic fallback.

        Args:
            use_redis: Attempt to use Redis backend if True.
            **kwargs: Additional arguments for backend initialization.

        Returns:
            Initialized EventBusBase instance.
        """
        with cls._lock:
            if cls._instance is not None:
                return cls._instance

            if use_redis:
                try:
                    cls._instance = RedisEventBus(**kwargs)
                    logger.info("EventBus initialized with Redis backend")
                except (ImportError, Exception) as e:
                    logger.warning(f"Redis initialization failed: {e}. Falling back to InMemory backend")
                    cls._instance = InMemoryEventBus()
            else:
                cls._instance = InMemoryEventBus()
                logger.info("EventBus initialized with InMemory backend")

            return cls._instance

    @classmethod
    def get_instance(cls) -> EventBusBase:
        """
        Get the current event bus instance.

        Returns:
            Current EventBusBase instance (initializes if needed).
        """
        if cls._instance is None:
            cls.initialize()
        return cls._instance

    @classmethod
    def shutdown(cls) -> None:
        """Shutdown the event bus."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.shutdown()
                cls._instance = None
            logger.info("EventBus shutdown complete")
