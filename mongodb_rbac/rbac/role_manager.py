from datetime import datetime
import logging
import re
from utils.db_connection import DatabaseConnection
from models.user_model import User
from rbac.permissions import ROLE_PERMISSIONS
from pymongo.errors import DuplicateKeyError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RoleManager:
    def __init__(self):
        self.db = DatabaseConnection().get_database()
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create necessary indexes for the users collection"""
        try:
            self.db.users.create_index("username", unique=True)
            logger.info("Database indexes ensured")
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")
            raise

    def _validate_username(self, username):
        """Validate username format and requirements"""
        if not username:
            raise ValueError("Username cannot be empty")
        
        if not isinstance(username, str):
            raise ValueError("Username must be a string")
            
        # Username should be alphanumeric with underscores, 3-32 characters
        if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
            raise ValueError(
                "Invalid username format. Username must be 3-32 characters long "
                "and contain only letters, numbers, and underscores"
            )

    def _validate_password(self, password):
        """Validate password requirements"""
        if not password:
            raise ValueError("Password cannot be empty")
            
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
            
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
            
        # Check for at least one uppercase, one lowercase, and one number
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$', password):
            raise ValueError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, and one number"
            )

    def _validate_role(self, role):
        """Validate role existence and permissions"""
        if not role:
            raise ValueError("Role cannot be empty")
            
        if role not in ROLE_PERMISSIONS:
            raise ValueError(
                f"Invalid role: {role}. Valid roles are: {', '.join(ROLE_PERMISSIONS.keys())}"
            )

    def create_user(self, username, password, role):
        """
        Create a new user with specified role and validated inputs
        
        Args:
            username (str): Username for the new user
            password (str): Password for the new user
            role (str): Role to assign to the user
            
        Returns:
            ObjectId: The ID of the created user
            
        Raises:
            ValueError: If any input validation fails
            DuplicateKeyError: If username already exists
        """
        try:
            # Validate all inputs
            self._validate_username(username)
            self._validate_password(password)
            self._validate_role(role)
            
            user = User(
                username=username,
                role=role,
                permissions=ROLE_PERMISSIONS[role]["permissions"],
                accessible_collections=ROLE_PERMISSIONS[role]["collections"]
            )

            user_dict = user.to_dict()
            user_dict["password"] = password  # In production, use password hashing
            user_dict["created_at"] = datetime.utcnow()
            
            result = self.db.users.insert_one(user_dict)
            logger.info(f"Created user {username} with role {role}")
            return result.inserted_id
            
        except DuplicateKeyError:
            logger.error(f"User {username} already exists")
            raise
        except ValueError as e:
            logger.error(f"Validation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise

    def update_user_role(self, username, new_role):
        """Update a user's role with validation"""
        try:
            self._validate_role(new_role)
            
            result = self.db.users.update_one(
                {"username": username},
                {
                    "$set": {
                        "role": new_role,
                        "permissions": ROLE_PERMISSIONS[new_role]["permissions"],
                        "accessible_collections": ROLE_PERMISSIONS[new_role]["collections"],
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            
            if result.modified_count == 0:
                raise ValueError(f"User {username} not found")
                
            logger.info(f"Updated role for user {username} to {new_role}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating user role: {e}")
            raise

    def check_permission(self, username, action, collection):
        """Check if a user has permission to perform an action on a collection"""
        try:
            if not username or not action or not collection:
                return False
                
            user = self.db.users.find_one({"username": username})
            if not user:
                logger.warning(f"User {username} not found")
                return False

            # Check if user has access to all collections or specific collection
            if "*" in user["accessible_collections"] or collection in user["accessible_collections"]:
                has_permission = action in user["permissions"]
                logger.info(
                    f"Permission check for {username} - Action: {action}, "
                    f"Collection: {collection}, Result: {has_permission}"
                )
                return has_permission
            return False
            
        except Exception as e:
            logger.error(f"Error checking permissions: {e}")
            raise

    def delete_user(self, username):
        """Delete a user with validation"""
        try:
            if not username:
                raise ValueError("Username cannot be empty")
                
            result = self.db.users.delete_one({"username": username})
            if result.deleted_count == 0:
                raise ValueError(f"User {username} not found")
                
            logger.info(f"Deleted user {username}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            raise

    def get_user_info(self, username):
        """Get user information"""
        try:
            if not username:
                raise ValueError("Username cannot be empty")
                
            user = self.db.users.find_one({"username": username})
            if not user:
                raise ValueError(f"User {username} not found")
                
            # Remove sensitive information
            user.pop('password', None)
            return user
            
        except Exception as e:
            logger.error(f"Error retrieving user info: {e}")
            raise
