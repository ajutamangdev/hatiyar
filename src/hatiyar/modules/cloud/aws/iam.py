"""AWS IAM Enumeration Module"""

from typing import Dict, Any
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from hatiyar.core.module_base import ModuleBase, ModuleType
from hatiyar.utils.output import save_json_results

console = Console()


class Module(ModuleBase):
    """AWS IAM enumeration including users, roles, policies, MFA status, and security analysis."""

    NAME = "iam_enumeration"
    DESCRIPTION = "AWS IAM users, roles, policies, and security enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_USERS": True,
        "ENUMERATE_GROUPS": True,
        "ENUMERATE_ROLES": True,
        "ENUMERATE_POLICIES": True,
        "CHECK_PASSWORD_POLICY": True,
        "CHECK_MFA": True,
        "GENERATE_CREDENTIAL_REPORT": False,
        "OUTPUT_FILE": "iam_enumeration_results.json",
    }

    REQUIRED_OPTIONS = []

    def __init__(self):
        super().__init__()
        self.iam_client = None
        self.sts_client = None
        self.data = {
            "account_id": "",
            "users": [],
            "groups": [],
            "roles": [],
            "policies": [],
            "password_policy": {},
            "account_summary": {},
            "security_findings": [],
            "users_without_mfa": [],
            "users_with_old_keys": [],
            "inactive_users": [],
            "overprivileged_roles": [],
        }

    def initialize_client(self) -> bool:
        """Initialize AWS IAM client with multiple credential options"""
        try:
            session_kwargs = {
                "region_name": self.options.get("AWS_REGION", "us-east-1")
            }

            if self.options.get("AWS_PROFILE"):
                session_kwargs["profile_name"] = self.options["AWS_PROFILE"]
                console.print(
                    f"[dim]Using AWS profile: {self.options['AWS_PROFILE']}[/dim]"
                )

            elif self.options.get("ACCESS_KEY") and self.options.get("SECRET_KEY"):
                session_kwargs["aws_access_key_id"] = self.options["ACCESS_KEY"]
                session_kwargs["aws_secret_access_key"] = self.options["SECRET_KEY"]
                if self.options.get("SESSION_TOKEN"):
                    session_kwargs["aws_session_token"] = self.options["SESSION_TOKEN"]

            else:
                console.print("[dim]Using default AWS credentials[/dim]")

            session = boto3.Session(**session_kwargs)
            self.iam_client = session.client("iam")
            self.sts_client = session.client("sts")

            # Get account ID
            identity = self.sts_client.get_caller_identity()
            self.data["account_id"] = identity.get("Account", "")

            # Test IAM access
            self.iam_client.list_users(MaxItems=1)
            console.print(
                f"[green]✓[/green] Connected to AWS IAM (Account: {self.data['account_id']})"
            )
            return True

        except NoCredentialsError:
            console.print(
                "[red]✗[/red] No AWS credentials found. Configure AWS CLI, set profile, or provide credentials."
            )
            console.print(
                "[yellow]Hint:[/yellow] Set ACCESS_KEY and SECRET_KEY options, or configure ~/.aws/credentials"
            )
            return False
        except PartialCredentialsError:
            console.print("[red]✗[/red] Incomplete AWS credentials provided.")
            return False
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                console.print("[red]✗[/red] Access denied. Check IAM permissions.")
                console.print(
                    "[yellow]Required:[/yellow] iam:ListUsers, iam:GetAccountSummary"
                )
            else:
                console.print(
                    f"[red]✗[/red] AWS error: {e.response['Error']['Message']}"
                )
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize IAM client: {str(e)}")
            return False

    def get_account_summary(self):
        """Get IAM account summary"""
        try:
            response = self.iam_client.get_account_summary()
            self.data["account_summary"] = response.get("SummaryMap", {})

            console.print("\n[bold cyan]═══ IAM Account Summary ═══[/bold cyan]")
            summary = self.data["account_summary"]

            table = Table(show_header=False)
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="green", justify="right")

            table.add_row("Users", str(summary.get("Users", 0)))
            table.add_row("Groups", str(summary.get("Groups", 0)))
            table.add_row("Roles", str(summary.get("Roles", 0)))
            table.add_row("Policies", str(summary.get("Policies", 0)))
            table.add_row("MFA Devices", str(summary.get("MFADevices", 0)))
            table.add_row(
                "Account MFA Enabled", str(summary.get("AccountMFAEnabled", 0))
            )

            console.print(table)

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Could not retrieve account summary: {str(e)}"
            )

    def get_password_policy(self):
        """Get IAM password policy"""
        if not self.options.get("CHECK_PASSWORD_POLICY"):
            return

        try:
            response = self.iam_client.get_account_password_policy()
            policy = response.get("PasswordPolicy", {})
            self.data["password_policy"] = policy

            console.print("\n[bold cyan]═══ Password Policy ═══[/bold cyan]")

            # Check policy strength
            strong = all(
                [
                    policy.get("MinimumPasswordLength", 0) >= 14,
                    policy.get("RequireSymbols", False),
                    policy.get("RequireNumbers", False),
                    policy.get("RequireUppercaseCharacters", False),
                    policy.get("RequireLowercaseCharacters", False),
                    policy.get("MaxPasswordAge", 0) > 0,
                ]
            )

            status = "[green]✓ Strong[/green]" if strong else "[yellow]⚠ Weak[/yellow]"

            panel_content = (
                f"[bold]Status:[/bold] {status}\n\n"
                f"Min Length: {policy.get('MinimumPasswordLength', 'Not set')}\n"
                f"Require Symbols: {policy.get('RequireSymbols', False)}\n"
                f"Require Numbers: {policy.get('RequireNumbers', False)}\n"
                f"Require Uppercase: {policy.get('RequireUppercaseCharacters', False)}\n"
                f"Require Lowercase: {policy.get('RequireLowercaseCharacters', False)}\n"
                f"Max Password Age: {policy.get('MaxPasswordAge', 'Not set')} days\n"
                f"Password Reuse Prevention: {policy.get('PasswordReusePrevention', 'Not set')}\n"
                f"Hard Expiry: {policy.get('HardExpiry', False)}\n"
                f"Allow Users to Change: {policy.get('AllowUsersToChangePassword', False)}\n"
                f"Expire Passwords: {policy.get('ExpirePasswords', False)}"
            )

            console.print(Panel(panel_content, title="Password Policy", expand=False))

            # Add findings
            if not strong:
                self.data["security_findings"].append("Weak password policy detected")

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                console.print("[yellow]⚠[/yellow] No password policy configured")
                self.data["security_findings"].append("No password policy configured")
            else:
                console.print(
                    f"[yellow]⚠[/yellow] Could not retrieve password policy: {str(e)}"
                )

    def enumerate_users(self):
        """Enumerate all IAM users with detailed information"""
        if not self.options.get("ENUMERATE_USERS"):
            return

        console.print("\n[bold cyan]═══ Enumerating IAM Users ═══[/bold cyan]")

        try:
            paginator = self.iam_client.get_paginator("list_users")
            user_count = 0

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_count += 1
                    username = user.get("UserName", "")

                    console.print(f"\n[cyan]User {user_count}:[/cyan] {username}")

                    # Get detailed user information
                    user_info = self._get_user_details(username, user)
                    self.data["users"].append(user_info)

                    # Display user panel
                    self._display_user_panel(user_info)

                    # Check for security issues
                    self._check_user_security(user_info)

            console.print(f"\n[green]✓[/green] Found {user_count} users")

        except ClientError as e:
            console.print(
                f"[red]✗[/red] Error enumerating users: {e.response['Error']['Message']}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _get_user_details(self, username: str, user_data: Dict) -> Dict[str, Any]:
        """Get detailed information about a user"""
        user_info = {
            "username": username,
            "user_id": user_data.get("UserId", ""),
            "arn": user_data.get("Arn", ""),
            "created_date": str(user_data.get("CreateDate", "")),
            "password_last_used": str(user_data.get("PasswordLastUsed", ""))
            if user_data.get("PasswordLastUsed")
            else "Never",
            "access_keys": [],
            "mfa_devices": [],
            "groups": [],
            "attached_policies": [],
            "inline_policies": [],
            "tags": [],
        }

        # Get access keys
        try:
            keys_response = self.iam_client.list_access_keys(UserName=username)
            for key in keys_response.get("AccessKeyMetadata", []):
                key_info = {
                    "access_key_id": key.get("AccessKeyId", ""),
                    "status": key.get("Status", ""),
                    "created_date": str(key.get("CreateDate", "")),
                }

                # Get last used info
                try:
                    last_used = self.iam_client.get_access_key_last_used(
                        AccessKeyId=key.get("AccessKeyId")
                    )
                    key_info["last_used"] = str(
                        last_used.get("AccessKeyLastUsed", {}).get(
                            "LastUsedDate", "Never"
                        )
                    )
                    key_info["last_service"] = last_used.get(
                        "AccessKeyLastUsed", {}
                    ).get("ServiceName", "N/A")
                except Exception:
                    key_info["last_used"] = "Unknown"

                user_info["access_keys"].append(key_info)
        except Exception:
            pass

        # Get MFA devices
        try:
            mfa_response = self.iam_client.list_mfa_devices(UserName=username)
            user_info["mfa_devices"] = [
                {
                    "serial_number": device.get("SerialNumber", ""),
                    "enabled_date": str(device.get("EnableDate", "")),
                }
                for device in mfa_response.get("MFADevices", [])
            ]
        except Exception:
            pass

        # Get groups
        try:
            groups_response = self.iam_client.list_groups_for_user(UserName=username)
            user_info["groups"] = [
                g.get("GroupName", "") for g in groups_response.get("Groups", [])
            ]
        except Exception:
            pass

        # Get attached managed policies
        try:
            policies_response = self.iam_client.list_attached_user_policies(
                UserName=username
            )
            user_info["attached_policies"] = [
                {
                    "name": p.get("PolicyName", ""),
                    "arn": p.get("PolicyArn", ""),
                }
                for p in policies_response.get("AttachedPolicies", [])
            ]
        except Exception:
            pass

        # Get inline policies
        try:
            inline_response = self.iam_client.list_user_policies(UserName=username)
            user_info["inline_policies"] = inline_response.get("PolicyNames", [])
        except Exception:
            pass

        # Get tags
        try:
            tags_response = self.iam_client.list_user_tags(UserName=username)
            user_info["tags"] = tags_response.get("Tags", [])
        except Exception:
            pass

        return user_info

    def _display_user_panel(self, user_info: Dict[str, Any]):
        """Display user information in a formatted panel"""
        mfa_status = "✓ Enabled" if user_info.get("mfa_devices") else "✗ Disabled"
        mfa_color = "green" if user_info.get("mfa_devices") else "red"

        access_keys_count = len(user_info.get("access_keys", []))
        active_keys = len(
            [k for k in user_info.get("access_keys", []) if k.get("status") == "Active"]
        )

        panel_content = (
            f"[bold]ARN:[/bold] {user_info.get('arn', 'N/A')}\n"
            f"[bold]User ID:[/bold] {user_info.get('user_id', 'N/A')}\n"
            f"[bold]Created:[/bold] {user_info.get('created_date', 'N/A')}\n\n"
            f"[bold cyan]Security:[/bold cyan]\n"
            f"  MFA: [{mfa_color}]{mfa_status}[/{mfa_color}]\n"
            f"  Access Keys: {active_keys}/{access_keys_count} active\n"
            f"  Password Last Used: {user_info.get('password_last_used', 'Never')}\n\n"
        )

        # Access keys details
        if user_info.get("access_keys"):
            panel_content += "[bold cyan]Access Keys:[/bold cyan]\n"
            for key in user_info.get("access_keys", []):
                status_color = "green" if key.get("status") == "Active" else "yellow"
                panel_content += (
                    f"  • {key.get('access_key_id')} "
                    f"[{status_color}]{key.get('status')}[/{status_color}] "
                    f"(Created: {key.get('created_date', 'N/A')}, "
                    f"Last Used: {key.get('last_used', 'Never')})\n"
                )
            panel_content += "\n"

        # Groups
        if user_info.get("groups"):
            panel_content += f"[bold cyan]Groups:[/bold cyan] {', '.join(user_info.get('groups', []))}\n\n"

        # Policies
        if user_info.get("attached_policies") or user_info.get("inline_policies"):
            panel_content += "[bold cyan]Policies:[/bold cyan]\n"
            for policy in user_info.get("attached_policies", []):
                panel_content += f"  • {policy.get('name')} (Managed)\n"
            for policy_name in user_info.get("inline_policies", []):
                panel_content += f"  • {policy_name} (Inline)\n"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{user_info.get('username')}[/bold]",
                expand=False,
            )
        )

    def _check_user_security(self, user_info: Dict[str, Any]):
        """Check user for security issues"""
        username = user_info.get("username")

        # Check MFA
        if self.options.get("CHECK_MFA") and not user_info.get("mfa_devices"):
            self.data["users_without_mfa"].append(username)
            self.data["security_findings"].append(
                f"User '{username}' does not have MFA enabled"
            )

        # Check access key age (older than 90 days)
        from datetime import datetime, timezone

        for key in user_info.get("access_keys", []):
            if key.get("created_date"):
                try:
                    created = datetime.fromisoformat(
                        key["created_date"].replace("Z", "+00:00")
                    )
                    age_days = (datetime.now(timezone.utc) - created).days
                    if age_days > 90:
                        self.data["users_with_old_keys"].append(username)
                        self.data["security_findings"].append(
                            f"User '{username}' has access key older than 90 days ({age_days} days)"
                        )
                except Exception:
                    pass

        # Check inactive users (password never used or not used in 90+ days)
        if user_info.get("password_last_used") == "Never":
            self.data["inactive_users"].append(username)

    def enumerate_groups(self):
        """Enumerate all IAM groups"""
        if not self.options.get("ENUMERATE_GROUPS"):
            return

        console.print("\n[bold cyan]═══ Enumerating IAM Groups ═══[/bold cyan]")

        try:
            paginator = self.iam_client.get_paginator("list_groups")
            group_count = 0

            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    group_count += 1
                    group_name = group.get("GroupName", "")

                    group_info = {
                        "name": group_name,
                        "arn": group.get("Arn", ""),
                        "created_date": str(group.get("CreateDate", "")),
                        "attached_policies": [],
                        "inline_policies": [],
                    }

                    # Get attached policies
                    try:
                        policies = self.iam_client.list_attached_group_policies(
                            GroupName=group_name
                        )
                        group_info["attached_policies"] = [
                            p.get("PolicyName", "")
                            for p in policies.get("AttachedPolicies", [])
                        ]
                    except Exception:
                        pass

                    # Get inline policies
                    try:
                        inline = self.iam_client.list_group_policies(
                            GroupName=group_name
                        )
                        group_info["inline_policies"] = inline.get("PolicyNames", [])
                    except Exception:
                        pass

                    self.data["groups"].append(group_info)
                    console.print(
                        f"  • {group_name} ({len(group_info['attached_policies'])} policies)"
                    )

            console.print(f"\n[green]✓[/green] Found {group_count} groups")

        except Exception as e:
            console.print(f"[red]✗[/red] Error enumerating groups: {str(e)}")

    def enumerate_roles(self):
        """Enumerate all IAM roles"""
        if not self.options.get("ENUMERATE_ROLES"):
            return

        console.print("\n[bold cyan]═══ Enumerating IAM Roles ═══[/bold cyan]")

        try:
            paginator = self.iam_client.get_paginator("list_roles")
            role_count = 0

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_count += 1
                    role_name = role.get("RoleName", "")

                    role_info = {
                        "name": role_name,
                        "arn": role.get("Arn", ""),
                        "created_date": str(role.get("CreateDate", "")),
                        "description": role.get("Description", ""),
                        "max_session_duration": role.get("MaxSessionDuration", 3600),
                        "assume_role_policy": role.get("AssumeRolePolicyDocument", {}),
                        "attached_policies": [],
                        "inline_policies": [],
                    }

                    # Get attached policies
                    try:
                        policies = self.iam_client.list_attached_role_policies(
                            RoleName=role_name
                        )
                        role_info["attached_policies"] = [
                            {
                                "name": p.get("PolicyName", ""),
                                "arn": p.get("PolicyArn", ""),
                            }
                            for p in policies.get("AttachedPolicies", [])
                        ]
                    except Exception:
                        pass

                    # Get inline policies
                    try:
                        inline = self.iam_client.list_role_policies(RoleName=role_name)
                        role_info["inline_policies"] = inline.get("PolicyNames", [])
                    except Exception:
                        pass

                    self.data["roles"].append(role_info)

                    # Check for overprivileged roles (AdministratorAccess)
                    for policy in role_info["attached_policies"]:
                        if "AdministratorAccess" in policy.get("name", ""):
                            self.data["overprivileged_roles"].append(role_name)
                            break

                    if role_count <= 10:  # Show first 10
                        console.print(
                            f"  • {role_name} ({len(role_info['attached_policies'])} policies)"
                        )

            if role_count > 10:
                console.print(f"  ... and {role_count - 10} more roles")

            console.print(f"\n[green]✓[/green] Found {role_count} roles")

        except Exception as e:
            console.print(f"[red]✗[/red] Error enumerating roles: {str(e)}")

    def enumerate_policies(self):
        """Enumerate IAM policies (customer managed only)"""
        if not self.options.get("ENUMERATE_POLICIES"):
            return

        console.print("\n[bold cyan]═══ Enumerating IAM Policies ═══[/bold cyan]")

        try:
            paginator = self.iam_client.get_paginator("list_policies")
            policy_count = 0

            # Only list customer managed policies
            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_count += 1

                    policy_info = {
                        "name": policy.get("PolicyName", ""),
                        "arn": policy.get("Arn", ""),
                        "created_date": str(policy.get("CreateDate", "")),
                        "updated_date": str(policy.get("UpdateDate", "")),
                        "attachment_count": policy.get("AttachmentCount", 0),
                        "is_attachable": policy.get("IsAttachable", False),
                    }

                    self.data["policies"].append(policy_info)

            console.print(
                f"\n[green]✓[/green] Found {policy_count} customer managed policies"
            )

        except Exception as e:
            console.print(f"[red]✗[/red] Error enumerating policies: {str(e)}")

    def save_results(self) -> str:
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"iam_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)

            result_data = {
                "metadata": {
                    "scan_date": datetime.now().isoformat(),
                    "account_id": self.data["account_id"],
                    "module": self.NAME,
                    "version": self.VERSION,
                },
                "summary": {
                    "users": len(self.data["users"]),
                    "groups": len(self.data["groups"]),
                    "roles": len(self.data["roles"]),
                    "policies": len(self.data["policies"]),
                    "users_without_mfa": len(self.data["users_without_mfa"]),
                    "users_with_old_keys": len(self.data["users_with_old_keys"]),
                    "inactive_users": len(self.data["inactive_users"]),
                    "overprivileged_roles": len(self.data["overprivileged_roles"]),
                    "security_findings": len(self.data["security_findings"]),
                },
                "account_summary": self.data["account_summary"],
                "password_policy": self.data["password_policy"],
                "users": self.data["users"],
                "groups": self.data["groups"],
                "roles": self.data["roles"],
                "policies": self.data["policies"],
                "security_findings": self.data["security_findings"],
            }

            save_json_results(result_data, output_path)
            console.print(f"\n[green]✓[/green] Results saved to: {output_file}")
            return output_file

        except (IOError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            return ""

    def run(self) -> Dict[str, Any]:
        """Execute IAM enumeration"""

        panel = Panel(
            "[bold cyan]AWS IAM Enumeration[/bold cyan]\n"
            "[dim]Collecting users, groups, roles, policies, and security configuration[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize client
        if not self.initialize_client():
            return {
                "success": False,
                "status": "failed",
                "message": "Failed to initialize AWS IAM client",
            }

        # Get account summary and password policy
        self.get_account_summary()
        self.get_password_policy()

        # Execute enumeration
        self.enumerate_users()
        self.enumerate_groups()
        self.enumerate_roles()
        self.enumerate_policies()

        # Save results
        output_file = self.save_results()

        # Summary
        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(
            f"[bold]IAM Resources:[/bold] {len(self.data['users'])} Users, "
            f"{len(self.data['groups'])} Groups, "
            f"{len(self.data['roles'])} Roles, "
            f"{len(self.data['policies'])} Policies"
        )

        # Security summary
        if self.data["users_without_mfa"]:
            console.print(
                f"[yellow]⚠[/yellow] {len(self.data['users_without_mfa'])} users without MFA: "
                f"{', '.join(self.data['users_without_mfa'][:3])}"
                f"{' ...' if len(self.data['users_without_mfa']) > 3 else ''}"
            )

        if self.data["users_with_old_keys"]:
            console.print(
                f"[yellow]⚠[/yellow] {len(self.data['users_with_old_keys'])} users with old access keys (>90 days)"
            )

        if self.data["overprivileged_roles"]:
            console.print(
                f"[yellow]⚠[/yellow] {len(self.data['overprivileged_roles'])} roles with AdministratorAccess"
            )

        if self.data["security_findings"]:
            console.print(
                f"\n[yellow]⚠[/yellow] Total Security Findings: {len(self.data['security_findings'])}"
            )

        return {
            "success": True,
            "status": "completed",
            "message": f"Enumeration complete. Results saved to {output_file}",
            "output_file": output_file,
            "summary": {
                "users": len(self.data["users"]),
                "groups": len(self.data["groups"]),
                "roles": len(self.data["roles"]),
                "policies": len(self.data["policies"]),
                "security": {
                    "users_without_mfa": len(self.data["users_without_mfa"]),
                    "users_with_old_keys": len(self.data["users_with_old_keys"]),
                    "inactive_users": len(self.data["inactive_users"]),
                    "overprivileged_roles": len(self.data["overprivileged_roles"]),
                    "total_findings": len(self.data["security_findings"]),
                },
            },
        }
