"""
agentadmit.storage
------------------
Abstract storage interface + MongoDB implementation.

The SDK is DB-agnostic. App owners can use MongoDB (default), PostgreSQL,
SQLite, or provide their own storage backend.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract storage interface for AgentAdmit data."""

    @abstractmethod
    def store_connection(self, connection: dict) -> None:
        """Store a new agent connection record."""
        ...

    @abstractmethod
    def get_connection(self, connection_id: str) -> Optional[dict]:
        """Get a connection by connection_id. Returns None if not found."""
        ...

    @abstractmethod
    def get_active_connection(self, connection_id: str) -> Optional[dict]:
        """Get a connection only if status == 'active'."""
        ...

    @abstractmethod
    def update_connection(self, connection_id: str, updates: dict) -> bool:
        """Update fields on a connection. Returns True if updated."""
        ...

    @abstractmethod
    def revoke_connection(self, connection_id: str) -> bool:
        """Set connection status to 'revoked'. Returns True if found and revoked."""
        ...

    @abstractmethod
    def list_connections(self, user_id: str) -> list[dict]:
        """List all connections for a user (active, revoked, expired)."""
        ...

    @abstractmethod
    def count_active_connections(self, user_id: str) -> int:
        """Count active connections for a user."""
        ...

    @abstractmethod
    def store_token(self, token_record: dict) -> None:
        """Store a connection token record (for single-use verification)."""
        ...

    @abstractmethod
    def get_token(self, token_hash: str) -> Optional[dict]:
        """Get a connection token by its hash."""
        ...

    @abstractmethod
    def mark_token_used(self, token_hash: str) -> bool:
        """Mark a connection token as used. Returns True if updated."""
        ...

    @abstractmethod
    def log_access(self, entry: dict) -> None:
        """Write an audit log entry."""
        ...

    @abstractmethod
    def count_audit_calls(self, user_id: str, period_start: datetime, period_end: datetime) -> int:
        """Count API verification calls in a billing period."""
        ...

    @abstractmethod
    def get_user(self, user_id: str, lookup_field: str = "user_id") -> Optional[dict]:
        """Look up a user by ID. The lookup_field is configurable per app."""
        ...


class MongoDBStorage(StorageBackend):
    """MongoDB storage implementation (default)."""

    def __init__(self, uri: str, database: str, connections_collection: str,
                 audit_log_collection: str, tokens_collection: str):
        from pymongo import MongoClient
        self.client = MongoClient(uri)
        self.db = self.client[database]
        self.connections = self.db[connections_collection]
        self.audit_log = self.db[audit_log_collection]
        self.tokens = self.db[tokens_collection]
        # Users collection is app-specific — set via set_users_collection
        self._users = None

        # Create indexes
        self.connections.create_index("connection_id", unique=True)
        self.connections.create_index([("user_id", 1), ("status", 1)])
        self.tokens.create_index("token_hash", unique=True)
        self.tokens.create_index("expires_at", expireAfterSeconds=0)
        self.audit_log.create_index([("user_id", 1), ("timestamp", -1)])

        logger.info("AgentAdmit MongoDB storage initialized: %s/%s", uri.split("@")[-1] if "@" in uri else "localhost", database)

    def set_users_collection(self, collection_name: str):
        """Set the app's users collection for user lookups."""
        self._users = self.db[collection_name]

    def store_connection(self, connection: dict) -> None:
        self.connections.insert_one(connection)

    def get_connection(self, connection_id: str) -> Optional[dict]:
        return self.connections.find_one({"connection_id": connection_id})

    def get_active_connection(self, connection_id: str) -> Optional[dict]:
        return self.connections.find_one({"connection_id": connection_id, "status": "active"})

    def update_connection(self, connection_id: str, updates: dict) -> bool:
        result = self.connections.update_one(
            {"connection_id": connection_id},
            {"$set": updates}
        )
        return result.modified_count > 0

    def revoke_connection(self, connection_id: str) -> bool:
        result = self.connections.update_one(
            {"connection_id": connection_id, "status": "active"},
            {"$set": {"status": "revoked", "revoked_at": datetime.utcnow()}}
        )
        return result.modified_count > 0

    def list_connections(self, user_id: str) -> list[dict]:
        cursor = self.connections.find(
            {"user_id": user_id},
            {"_id": 0}
        ).sort("created_at", -1)
        return list(cursor)

    def count_active_connections(self, user_id: str) -> int:
        return self.connections.count_documents({"user_id": user_id, "status": "active"})

    def store_token(self, token_record: dict) -> None:
        self.tokens.insert_one(token_record)

    def get_token(self, token_hash: str) -> Optional[dict]:
        return self.tokens.find_one({"token_hash": token_hash})

    def mark_token_used(self, token_hash: str) -> bool:
        result = self.tokens.update_one(
            {"token_hash": token_hash, "used": False},
            {"$set": {"used": True, "used_at": datetime.utcnow()}}
        )
        return result.modified_count > 0

    def log_access(self, entry: dict) -> None:
        try:
            self.audit_log.insert_one(entry)
        except Exception as exc:
            logger.error("Failed to write audit log: %s", exc)

    def count_audit_calls(self, user_id: str, period_start: datetime, period_end: datetime) -> int:
        return self.audit_log.count_documents({
            "user_id": user_id,
            "timestamp": {"$gte": period_start, "$lt": period_end},
        })

    def get_user(self, user_id: str, lookup_field: str = "user_id") -> Optional[dict]:
        if self._users is None:
            logger.warning("Users collection not set. Call storage.set_users_collection('your_users_collection')")
            return None
        return self._users.find_one({lookup_field: user_id})


class MemoryStorage(StorageBackend):
    """In-memory storage for testing and development."""

    def __init__(self):
        self._connections: dict[str, dict] = {}
        self._tokens: dict[str, dict] = {}
        self._audit_log: list[dict] = []
        self._users: dict[str, dict] = {}
        logger.info("AgentAdmit in-memory storage initialized (testing only)")

    def store_connection(self, connection: dict) -> None:
        self._connections[connection["connection_id"]] = connection

    def get_connection(self, connection_id: str) -> Optional[dict]:
        return self._connections.get(connection_id)

    def get_active_connection(self, connection_id: str) -> Optional[dict]:
        conn = self._connections.get(connection_id)
        if conn and conn.get("status") == "active":
            return conn
        return None

    def update_connection(self, connection_id: str, updates: dict) -> bool:
        if connection_id in self._connections:
            self._connections[connection_id].update(updates)
            return True
        return False

    def revoke_connection(self, connection_id: str) -> bool:
        conn = self._connections.get(connection_id)
        if conn and conn.get("status") == "active":
            conn["status"] = "revoked"
            conn["revoked_at"] = datetime.utcnow()
            return True
        return False

    def list_connections(self, user_id: str) -> list[dict]:
        return [c for c in self._connections.values() if c.get("user_id") == user_id]

    def count_active_connections(self, user_id: str) -> int:
        return sum(1 for c in self._connections.values()
                   if c.get("user_id") == user_id and c.get("status") == "active")

    def store_token(self, token_record: dict) -> None:
        self._tokens[token_record["token_hash"]] = token_record

    def get_token(self, token_hash: str) -> Optional[dict]:
        return self._tokens.get(token_hash)

    def mark_token_used(self, token_hash: str) -> bool:
        token = self._tokens.get(token_hash)
        if token and not token.get("used"):
            token["used"] = True
            token["used_at"] = datetime.utcnow()
            return True
        return False

    def log_access(self, entry: dict) -> None:
        self._audit_log.append(entry)

    def count_audit_calls(self, user_id: str, period_start: datetime, period_end: datetime) -> int:
        return sum(1 for e in self._audit_log
                   if e.get("user_id") == user_id
                   and period_start <= e.get("timestamp", datetime.min) < period_end)

    def get_user(self, user_id: str, lookup_field: str = "user_id") -> Optional[dict]:
        return self._users.get(user_id)

    def add_test_user(self, user_id: str, user_data: dict) -> None:
        """Helper for tests — add a user to the in-memory store."""
        self._users[user_id] = user_data


def create_storage(config) -> StorageBackend:
    """Factory: create the appropriate storage backend from config."""
    backend = config.storage.backend

    if backend == "mongodb":
        storage = MongoDBStorage(
            uri=config.storage.uri,
            database=config.storage.database,
            connections_collection=config.storage.connections_collection,
            audit_log_collection=config.storage.audit_log_collection,
            tokens_collection=config.storage.tokens_collection,
        )
        return storage

    elif backend == "memory":
        return MemoryStorage()

    else:
        from agentadmit.exceptions import ConfigurationError
        raise ConfigurationError(
            f"Unsupported storage backend: {backend}. "
            "Supported: 'mongodb', 'memory'. "
            "For PostgreSQL or SQLite, implement StorageBackend and pass it directly."
        )
