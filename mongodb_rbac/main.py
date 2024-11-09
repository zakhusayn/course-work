import os
import logging
from datetime import datetime
from rbac.role_manager import RoleManager
from utils.db_connection import DatabaseConnection
from pymongo.errors import DuplicateKeyError
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rbac.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
console = Console()

class RBACDemo:
    def __init__(self):
        self.role_manager = RoleManager()
        self.default_admin = {
            "username": "admin",
            "password": "AdminPass123!",
            "role": "Admin"
        }
        self.test_data = {
            "users": [
                ("john_scientist", "TestPass123!", "Data Scientist"),
                ("sarah_analyst", "AnalystPass123!", "Data Analyst"),
                ("mike_viewer", "ViewerPass123!", "Viewer"),
                ("admin_user", "AdminPass123!", "Admin"),
                ("senior_scientist", "SciPass123!", "Data Scientist"),
            ],
            "collections": [
                "sensitive_data",
                "analysis_results",
                "user_data",
                "logs",
                "reports"
            ],
            "actions": ["read", "write", "delete", "manage_users"]
        }

    def display_welcome(self):
        """Display welcome message and system information"""
        console.print(Panel.fit(
            "[bold blue]MongoDB RBAC Management System[/bold blue]\n"
            "[yellow]Version 1.0[/yellow]\n"
            f"Connected to database: {os.getenv('DATABASE_NAME', 'DSA4030A')}\n"
            f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="Welcome",
            border_style="blue"
        ))

    def validate_password(self, password):
        """Validate password meets requirements"""
        if not password:
            return False, "Password cannot be empty"
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        return True, "Password is valid"

    def setup_initial_admin(self):
        """Set up the initial admin user"""
        try:
            admin_username = os.getenv('ADMIN_USERNAME', self.default_admin["username"])
            admin_password = os.getenv('ADMIN_PASSWORD', self.default_admin["password"])
            
            # Validate password
            is_valid, message = self.validate_password(admin_password)
            if not is_valid:
                logger.error(f"Admin password validation failed: {message}")
                console.print(f"[red]Error: {message}")
                if Confirm.ask("Would you like to use the default admin password?"):
                    admin_password = self.default_admin["password"]
                else:
                    return False

            # Create admin user
            try:
                self.role_manager.create_user(
                    username=admin_username,
                    password=admin_password,
                    role="Admin"
                )
                console.print("[green]✓ Admin user created successfully")
                return True
            except DuplicateKeyError:
                console.print("[yellow]ℹ Admin user already exists")
                return True

        except Exception as e:
            logger.error(f"Error creating admin user: {e}")
            console.print(f"[red]✗ Error creating admin user: {e}")
            return False

    def create_test_users(self):
        """Create test users with different roles"""
        created_users = []
        with console.status("[bold green]Creating test users...") as status:
            for username, password, role in self.test_data["users"]:
                try:
                    self.role_manager.create_user(username, password, role)
                    created_users.append(username)
                    status.update(f"[green]✓ Created user: {username}")
                except DuplicateKeyError:
                    status.update(f"[yellow]ℹ User {username} already exists")
                except Exception as e:
                    status.update(f"[red]✗ Error creating {username}: {e}")
        
        return created_users

    def test_permissions(self):
        """Test and display permissions for all users"""
        table = Table(
            title="Permission Matrix",
            caption="✓ = Allowed, ✗ = Denied",
            caption_style="dim"
        )
        table.add_column("Username", style="cyan")
        table.add_column("Role", style="magenta")
        table.add_column("Collection", style="green")
        table.add_column("Action", style="yellow")
        table.add_column("Permission", style="bold")

        for username, _, role in self.test_data["users"]:
            for collection in self.test_data["collections"]:
                for action in self.test_data["actions"]:
                    has_permission = self.role_manager.check_permission(
                        username, action, collection
                    )
                    table.add_row(
                        username,
                        role,
                        collection,
                        action,
                        "[green]✓" if has_permission else "[red]✗"
                    )

        console.print(table)

    def demonstrate_role_transitions(self):
        """Demonstrate role transitions and permission changes"""
        transitions = [
            ("sarah_analyst", "Data Scientist", "Promotion"),
            ("john_scientist", "Admin", "Promotion"),
            ("mike_viewer", "Data Analyst", "Promotion")
        ]

        table = Table(title="Role Transitions")
        table.add_column("Username", style="cyan")
        table.add_column("From Role", style="yellow")
        table.add_column("To Role", style="green")
        table.add_column("Status", style="bold")

        for username, new_role, transition_type in transitions:
            try:
                original_role = self.role_manager.get_user_info(username)["role"]
                self.role_manager.update_user_role(username, new_role)
                table.add_row(
                    username,
                    original_role,
                    new_role,
                    "[green]✓ Success"
                )
            except Exception as e:
                table.add_row(
                    username,
                    "Unknown",
                    new_role,
                    f"[red]✗ Failed ({str(e)})"
                )

        console.print(table)

    def manage_users(self):
        """Interactive user management"""
        while True:
            console.clear()
            console.print("\n[bold]User Management[/bold]")
            choice = Prompt.ask(
                "Choose an action",
                choices=["1", "2", "3", "4", "5", "q"],
                default="q",
                show_choices=False
            )

            if choice == "1":
                # Create new user
                username = Prompt.ask("Enter username")
                password = Prompt.ask("Enter password", password=True)
                role = Prompt.ask("Enter role", choices=["Admin", "Data Scientist", "Data Analyst", "Viewer"])
                try:
                    self.role_manager.create_user(username, password, role)
                    console.print("[green]✓ User created successfully")
                except Exception as e:
                    console.print(f"[red]✗ Error: {e}")

            elif choice == "2":
                # Update user role
                username = Prompt.ask("Enter username")
                new_role = Prompt.ask("Enter new role", choices=["Admin", "Data Scientist", "Data Analyst", "Viewer"])
                try:
                    self.role_manager.update_user_role(username, new_role)
                    console.print("[green]✓ Role updated successfully")
                except Exception as e:
                    console.print(f"[red]✗ Error: {e}")

            elif choice == "3":
                # Delete user
                username = Prompt.ask("Enter username to delete")
                if Confirm.ask(f"Are you sure you want to delete user {username}?"):
                    try:
                        self.role_manager.delete_user(username)
                        console.print("[green]✓ User deleted successfully")
                    except Exception as e:
                        console.print(f"[red]✗ Error: {e}")

            elif choice == "4":
                # View user info
                username = Prompt.ask("Enter username")
                try:
                    user_info = self.role_manager.get_user_info(username)
                    console.print(Panel.fit(
                        "\n".join([f"{k}: {v}" for k, v in user_info.items() if k != 'password']),
                        title=f"User Information - {username}",
                        border_style="blue"
                    ))
                except Exception as e:
                    console.print(f"[red]✗ Error: {e}")

            elif choice == "5":
                # Test permissions
                username = Prompt.ask("Enter username")
                action = Prompt.ask("Enter action", choices=["read", "write", "delete", "manage_users"])
                collection = Prompt.ask("Enter collection")
                try:
                    has_permission = self.role_manager.check_permission(username, action, collection)
                    console.print(
                        f"[green]✓ Permission granted" if has_permission else "[red]✗ Permission denied"
                    )
                except Exception as e:
                    console.print(f"[red]✗ Error: {e}")

            elif choice.lower() == "q":
                break

            if choice != "q":
                Prompt.ask("\nPress Enter to continue")

def main():
    """Main function to demonstrate RBAC functionality"""
    parser = argparse.ArgumentParser(description='MongoDB RBAC Management System')
    parser.add_argument('--setup-admin', action='store_true', help='Setup initial admin user')
    parser.add_argument('--create-users', action='store_true', help='Create test users')
    parser.add_argument('--test-permissions', action='store_true', help='Test user permissions')
    parser.add_argument('--test-transitions', action='store_true', help='Test role transitions')
    parser.add_argument('--manage-users', action='store_true', help='Interactive user management')
    parser.add_argument('--run-all', action='store_true', help='Run all demonstrations')

    args = parser.parse_args()

    try:
        rbac_demo = RBACDemo()
        rbac_demo.display_welcome()

        if args.run_all or args.setup_admin:
            console.rule("[bold]Setting up Admin User")
            if not rbac_demo.setup_initial_admin():
                console.print("[red]Failed to set up admin user. Exiting...")
                return

        if args.run_all or args.create_users:
            console.rule("[bold]Creating Test Users")
            rbac_demo.create_test_users()

        if args.run_all or args.test_permissions:
            console.rule("[bold]Testing Permissions")
            rbac_demo.test_permissions()

        if args.run_all or args.test_transitions:
            console.rule("[bold]Testing Role Transitions")
            rbac_demo.demonstrate_role_transitions()

        if args.run_all or args.manage_users:
            console.rule("[bold]User Management")
            rbac_demo.manage_users()

    except Exception as e:
        logger.error(f"Error in main: {e}")
        console.print(f"[red]Error: {e}")
    finally:
        DatabaseConnection().close_connection()

if __name__ == "__main__":
    main()