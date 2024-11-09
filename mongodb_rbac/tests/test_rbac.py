import pytest
from datetime import datetime
from rbac.role_manager import RoleManager
from pymongo.errors import DuplicateKeyError
from bson.objectid import ObjectId
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestRBAC:
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test environment before each test"""
        self.role_manager = RoleManager()
        self.test_users = [
            # Basic test users
            "test_admin_user",
            "test_scientist_user",
            "test_analyst_user",
            # Role transition test users
            "test_role_user",
            "test_promotion_user",
            "test_demotion_user",
            # Permission test users
            "test_admin_combo",
            "test_scientist_combo",
            "test_analyst_combo",
            # Validation test users
            "test_validation_user",
            "test_edge_case_user",
            # Concurrent test users
            "test_concurrent_user",
            "test_concurrent_check_user",
            # Cleanup test users
            "test_cleanup_user",
            # Bulk operation test users
            "test_bulk_user",
            # Additional test users
            "test_duplicate_user",
            "test_inheritance_user",
        ]
        
        # Clean up MongoDB collection completely before tests
        self._cleanup_database()
        yield
        # Clean up after tests
        self._cleanup_database()

    def _cleanup_database(self):
        """Helper method to clean up the entire test database"""
        try:
            self.role_manager.db.users.delete_many({})
            logger.info("Database cleaned up successfully")
        except Exception as e:
            logger.error(f"Error during database cleanup: {e}")

    def test_create_user_basic(self):
        """Test basic user creation with different roles"""
        # Test creating admin user
        admin_id = self.role_manager.create_user("test_admin_user", "TestPass123", "Admin")
        assert isinstance(admin_id, ObjectId)
        
        # Test creating data scientist
        scientist_id = self.role_manager.create_user(
            "test_scientist_user", "TestPass123", "Data Scientist"
        )
        assert isinstance(scientist_id, ObjectId)
        
        # Test creating data analyst
        analyst_id = self.role_manager.create_user(
            "test_analyst_user", "TestPass123", "Data Analyst"
        )
        assert isinstance(analyst_id, ObjectId)

    def test_create_user_validation(self):
        """Test user creation with invalid inputs"""
        # Test empty username
        with pytest.raises(ValueError, match="Username cannot be empty"):
            self.role_manager.create_user("", "TestPass123", "Admin")
        
        # Test empty password
        with pytest.raises(ValueError, match="Password cannot be empty"):
            self.role_manager.create_user("test_admin_user", "", "Admin")
        
        # Test username with special characters
        with pytest.raises(ValueError, match="Invalid username format"):
            self.role_manager.create_user("test@user", "TestPass123", "Admin")
        
        # Test invalid role
        with pytest.raises(ValueError):
            self.role_manager.create_user("test_invalid", "TestPass123", "Invalid Role")

    def test_permissions(self):
        """Test basic permissions for different roles"""
        # Create test users
        self.role_manager.create_user("test_admin_user", "TestPass123", "Admin")
        self.role_manager.create_user("test_analyst_user", "TestPass123", "Data Analyst")

        # Test Admin permissions
        assert self.role_manager.check_permission("test_admin_user", "write", "any_collection")
        assert self.role_manager.check_permission("test_admin_user", "delete", "sensitive_data")

        # Test Data Analyst permissions
        assert self.role_manager.check_permission("test_analyst_user", "read", "sensitive_data")
        assert not self.role_manager.check_permission("test_analyst_user", "write", "sensitive_data")

    def test_update_user_role(self):
        """Test updating user roles"""
        # Create test user
        self.role_manager.create_user("test_role_user", "TestPass123", "Data Analyst")

        # Update role
        assert self.role_manager.update_user_role("test_role_user", "Data Scientist")

        # Verify new permissions
        assert self.role_manager.check_permission("test_role_user", "write", "sensitive_data")

        # Test invalid role update
        with pytest.raises(ValueError):
            self.role_manager.update_user_role("test_role_user", "Invalid Role")

    def test_delete_user_scenarios(self):
        """Test user deletion scenarios"""
        # Create test user
        self.role_manager.create_user("test_cleanup_user", "TestPass123", "Data Analyst")
        
        # Test successful deletion
        assert self.role_manager.delete_user("test_cleanup_user")
        
        # Test deleting non-existent user
        with pytest.raises(ValueError, match="User .* not found"):
            self.role_manager.delete_user("nonexistent_user")

    def test_role_permissions_admin(self):
        """Test comprehensive admin permissions"""
        self.role_manager.create_user("test_admin_user", "TestPass123", "Admin")
        
        # Test admin permissions on different collections
        collections = ["sensitive_data", "user_data", "analytics", "logs"]
        actions = ["read", "write", "delete", "manage_users"]
        
        for collection in collections:
            for action in actions:
                assert self.role_manager.check_permission(
                    "test_admin_user", action, collection
                ), f"Admin should have {action} permission on {collection}"

    def test_role_permissions_data_scientist(self):
        """Test comprehensive data scientist permissions"""
        self.role_manager.create_user(
            "test_scientist_user", "TestPass123", "Data Scientist"
        )
        
        # Test allowed actions
        allowed_collections = ["sensitive_data", "analysis_results", "model_data"]
        allowed_actions = ["read", "write"]
        
        for collection in allowed_collections:
            for action in allowed_actions:
                assert self.role_manager.check_permission(
                    "test_scientist_user", action, collection
                ), f"Data Scientist should have {action} permission on {collection}"
        
        # Test denied actions
        denied_actions = ["delete", "manage_users"]
        for action in denied_actions:
            assert not self.role_manager.check_permission(
                "test_scientist_user", action, allowed_collections[0]
            ), f"Data Scientist should not have {action} permission"

    def test_role_permissions_data_analyst(self):
        """Test comprehensive data analyst permissions"""
        self.role_manager.create_user(
            "test_analyst_user", "TestPass123", "Data Analyst"
        )
        
        # Test read-only permissions
        assert self.role_manager.check_permission(
            "test_analyst_user", "read", "sensitive_data"
        )
        
        # Test denied permissions
        denied_actions = ["write", "delete", "manage_users"]
        for action in denied_actions:
            assert not self.role_manager.check_permission(
                "test_analyst_user", action, "sensitive_data"
            ), f"Data Analyst should not have {action} permission"

    def test_bulk_operations(self):
        """Test performance with bulk operations"""
        users = []
        # Create multiple users
        for i in range(10):
            username = f"test_bulk_user_{i}"
            user_id = self.role_manager.create_user(username, "TestPass123", "Data Analyst")
            users.append(username)
            assert isinstance(user_id, ObjectId)
        
        # Update multiple users
        for username in users:
            assert self.role_manager.update_user_role(username, "Data Scientist")
        
        # Check permissions for multiple users
        for username in users:
            assert self.role_manager.check_permission(username, "write", "sensitive_data")

    @pytest.mark.parametrize("role,expected_permissions", [
        ("Admin", {"read", "write", "delete", "manage_users"}),
        ("Data Scientist", {"read", "write"}),
        ("Data Analyst", {"read"}),
    ])
    def test_role_specific_permissions(self, role, expected_permissions):
        """Test specific permissions for each role"""
        username = f"test_{role.lower().replace(' ', '_')}_user"
        self.role_manager.create_user(username, "TestPass123", role)
        
        # Test all possible permissions
        all_permissions = {"read", "write", "delete", "manage_users"}
        for permission in all_permissions:
            has_permission = self.role_manager.check_permission(
                username, permission, "sensitive_data"
            )
            if permission in expected_permissions:
                assert has_permission, f"{role} should have {permission} permission"
            else:
                assert not has_permission, f"{role} should not have {permission} permission"