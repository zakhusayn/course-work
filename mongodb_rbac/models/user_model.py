from datetime import datetime

class User:
    def __init__(self, username, role, permissions, accessible_collections):
        self.username = username
        self.role = role
        self.permissions = permissions
        self.accessible_collections = accessible_collections
        self.created_at = datetime.utcnow()
        self.last_login = None
        self.updated_at = None

    def to_dict(self):
        return {
            "username": self.username,
            "role": self.role,
            "permissions": self.permissions,
            "accessible_collections": self.accessible_collections,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "updated_at": self.updated_at
        }

    @classmethod
    def from_dict(cls, data):
        user = cls(
            username=data["username"],
            role=data["role"],
            permissions=data["permissions"],
            accessible_collections=data["accessible_collections"]
        )
        user.created_at = data.get("created_at")
        user.last_login = data.get("last_login")
        user.updated_at = data.get("updated_at")
        return user
        