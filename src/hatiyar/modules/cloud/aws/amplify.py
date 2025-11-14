"""AWS Amplify Enumeration Module"""

from typing import Dict, Any, List
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from hatiyar.core.module_base import ModuleBase, ModuleType
from hatiyar.utils.output import save_json_results

console = Console()


class Module(ModuleBase):
    """AWS Amplify enumeration including apps, branches, domains, and CI/CD configuration."""

    NAME = "amplify_enumeration"
    DESCRIPTION = "AWS Amplify application and deployment enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_APPS": True,
        "ENUMERATE_BRANCHES": True,
        "ENUMERATE_DOMAINS": True,
        "ENUMERATE_WEBHOOKS": True,
        "ENUMERATE_BACKEND_ENVS": True,
        "CHECK_ENV_VARS": True,
        "OUTPUT_FILE": "amplify_enumeration_results.json",
    }

    REQUIRED_OPTIONS = ["AWS_REGION"]

    def __init__(self):
        super().__init__()
        self.amplify_client = None
        self.data = {
            "apps": [],
            "branches": [],
            "domains": [],
            "webhooks": [],
            "backend_environments": [],
            "security_findings": [],
            "total_apps": 0,
            "total_branches": 0,
            "total_domains": 0,
            "apps_with_auto_branch_creation": [],
            "apps_with_custom_domains": [],
            "sensitive_env_vars": [],
        }

    def _get_session_kwargs(self) -> Dict[str, Any]:
        """Build AWS session configuration."""
        kwargs = {"region_name": self.options.get("AWS_REGION")}

        if self.options.get("AWS_PROFILE"):
            kwargs["profile_name"] = self.options.get("AWS_PROFILE")
        elif self.options.get("ACCESS_KEY") and self.options.get("SECRET_KEY"):
            kwargs["aws_access_key_id"] = self.options.get("ACCESS_KEY")
            kwargs["aws_secret_access_key"] = self.options.get("SECRET_KEY")
            if self.options.get("SESSION_TOKEN"):
                kwargs["aws_session_token"] = self.options.get("SESSION_TOKEN")

        return kwargs

    def initialize_client(self) -> bool:
        """Initialize AWS Amplify client."""
        try:
            session_kwargs = self._get_session_kwargs()

            session = boto3.Session(**session_kwargs)
            self.amplify_client = session.client("amplify")

            # Test connection
            self.amplify_client.list_apps(maxResults=1)
            console.print("[green]✓[/green] Successfully connected to AWS Amplify")
            return True

        except NoCredentialsError:
            console.print(
                "[red]✗[/red] No AWS credentials found. Please configure:\n"
                "  - AWS_PROFILE option, or\n"
                "  - ACCESS_KEY and SECRET_KEY options, or\n"
                "  - Default AWS credentials (~/.aws/credentials)"
            )
            return False
        except PartialCredentialsError:
            console.print("[red]✗[/red] Incomplete AWS credentials provided")
            return False
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] AWS API Error ({error_code}): {error_msg}\n"
                "[dim]Check your credentials and permissions[/dim]"
            )
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize Amplify client: {str(e)}")
            return False

    def enumerate_apps(self):
        """Enumerate all Amplify applications"""
        if not self.options.get("ENUMERATE_APPS"):
            return

        console.print(
            "\n[bold cyan]═══ Enumerating Amplify Applications ═══[/bold cyan]"
        )

        try:
            paginator = self.amplify_client.get_paginator("list_apps")

            for page in paginator.paginate():
                for app in page.get("apps", []):
                    app_id = app.get("appId")
                    app_name = app.get("name")
                    console.print(f"\n[bold]Processing:[/bold] {app_name}")

                    # Get detailed app info
                    app_details = self.amplify_client.get_app(appId=app_id)
                    app_info = app_details.get("app", {})

                    app_data = {
                        "id": app_id,
                        "arn": app_info.get("appArn"),
                        "name": app_name,
                        "description": app_info.get("description", ""),
                        "repository": app_info.get("repository"),
                        "platform": app_info.get("platform"),
                        "create_time": app_info.get("createTime"),
                        "update_time": app_info.get("updateTime"),
                        "environment_variables": app_info.get(
                            "environmentVariables", {}
                        ),
                        "default_domain": app_info.get("defaultDomain"),
                        "enable_branch_auto_build": app_info.get(
                            "enableBranchAutoBuild"
                        ),
                        "enable_branch_auto_deletion": app_info.get(
                            "enableBranchAutoDeletion"
                        ),
                        "enable_basic_auth": app_info.get("enableBasicAuth"),
                        "basic_auth_credentials": app_info.get("basicAuthCredentials"),
                        "custom_rules": app_info.get("customRules", []),
                        "production_branch": app_info.get("productionBranch"),
                        "build_spec": app_info.get("buildSpec"),
                        "custom_headers": app_info.get("customHeaders"),
                        "enable_auto_branch_creation": app_info.get(
                            "enableAutoBranchCreation"
                        ),
                        "auto_branch_creation_patterns": app_info.get(
                            "autoBranchCreationPatterns", []
                        ),
                        "auto_branch_creation_config": app_info.get(
                            "autoBranchCreationConfig"
                        ),
                        "iam_service_role_arn": app_info.get("iamServiceRoleArn"),
                        "tags": app_info.get("tags", {}),
                        "branches": [],
                        "domains": [],
                        "webhooks": [],
                        "backend_environments": [],
                    }

                    # Enumerate branches
                    if self.options.get("ENUMERATE_BRANCHES"):
                        app_data["branches"] = self._enumerate_branches(
                            app_id, app_name
                        )

                    # Enumerate domain associations
                    if self.options.get("ENUMERATE_DOMAINS"):
                        app_data["domains"] = self._enumerate_domains(app_id, app_name)

                    # Enumerate webhooks
                    if self.options.get("ENUMERATE_WEBHOOKS"):
                        app_data["webhooks"] = self._enumerate_webhooks(
                            app_id, app_name
                        )

                    # Enumerate backend environments
                    if self.options.get("ENUMERATE_BACKEND_ENVS"):
                        app_data["backend_environments"] = (
                            self._enumerate_backend_environments(app_id, app_name)
                        )

                    # Check for security findings
                    findings = self._check_app_security(app_data)
                    app_data["security_findings"] = findings
                    self.data["security_findings"].extend(findings)

                    # Track special configurations
                    if app_data.get("enable_auto_branch_creation"):
                        self.data["apps_with_auto_branch_creation"].append(app_name)

                    if app_data.get("domains"):
                        self.data["apps_with_custom_domains"].append(app_name)

                    self.data["apps"].append(app_data)
                    self.data["total_apps"] += 1

                    # Display app panel
                    self._display_app_panel(app_data)

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_apps']} Amplify applications"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] Error enumerating Amplify apps: {error_code} - {error_msg}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _enumerate_branches(self, app_id: str, app_name: str) -> List[Dict[str, Any]]:
        """Enumerate branches for an Amplify app"""
        branches = []

        try:
            paginator = self.amplify_client.get_paginator("list_branches")

            for page in paginator.paginate(appId=app_id):
                for branch in page.get("branches", []):
                    branch_name = branch.get("branchName")

                    # Get detailed branch info
                    branch_details = self.amplify_client.get_branch(
                        appId=app_id, branchName=branch_name
                    )
                    branch_info = branch_details.get("branch", {})

                    branch_data = {
                        "name": branch_name,
                        "arn": branch_info.get("branchArn"),
                        "stage": branch_info.get("stage"),
                        "display_name": branch_info.get("displayName"),
                        "description": branch_info.get("description", ""),
                        "enable_auto_build": branch_info.get("enableAutoBuild"),
                        "enable_pull_request_preview": branch_info.get(
                            "enablePullRequestPreview"
                        ),
                        "pull_request_environment_name": branch_info.get(
                            "pullRequestEnvironmentName"
                        ),
                        "backend_environment_arn": branch_info.get(
                            "backendEnvironmentArn"
                        ),
                        "total_number_of_jobs": branch_info.get("totalNumberOfJobs"),
                        "enable_basic_auth": branch_info.get("enableBasicAuth"),
                        "thumbnail_url": branch_info.get("thumbnailUrl"),
                        "framework": branch_info.get("framework"),
                        "active_job_id": branch_info.get("activeJobId"),
                        "environment_variables": branch_info.get(
                            "environmentVariables", {}
                        ),
                        "enable_notification": branch_info.get("enableNotification"),
                        "create_time": branch_info.get("createTime"),
                        "update_time": branch_info.get("updateTime"),
                        "tags": branch_info.get("tags", {}),
                    }

                    branches.append(branch_data)
                    self.data["branches"].append({"app_name": app_name, **branch_data})
                    self.data["total_branches"] += 1

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating branches for {app_name}: {str(e)}"
            )

        return branches

    def _enumerate_domains(self, app_id: str, app_name: str) -> List[Dict[str, Any]]:
        """Enumerate domain associations for an Amplify app"""
        domains = []

        try:
            paginator = self.amplify_client.get_paginator("list_domain_associations")

            for page in paginator.paginate(appId=app_id):
                for domain in page.get("domainAssociations", []):
                    domain_name = domain.get("domainName")

                    # Get detailed domain info
                    domain_details = self.amplify_client.get_domain_association(
                        appId=app_id, domainName=domain_name
                    )
                    domain_info = domain_details.get("domainAssociation", {})

                    domain_data = {
                        "name": domain_name,
                        "arn": domain_info.get("domainAssociationArn"),
                        "enable_auto_sub_domain": domain_info.get(
                            "enableAutoSubDomain"
                        ),
                        "auto_sub_domain_creation_patterns": domain_info.get(
                            "autoSubDomainCreationPatterns", []
                        ),
                        "auto_sub_domain_iam_role": domain_info.get(
                            "autoSubDomainIAMRole"
                        ),
                        "domain_status": domain_info.get("domainStatus"),
                        "status_reason": domain_info.get("statusReason", ""),
                        "certificate_verification_dns_record": domain_info.get(
                            "certificateVerificationDNSRecord"
                        ),
                        "sub_domains": domain_info.get("subDomains", []),
                    }

                    domains.append(domain_data)
                    self.data["domains"].append({"app_name": app_name, **domain_data})
                    self.data["total_domains"] += 1

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating domains for {app_name}: {str(e)}"
            )

        return domains

    def _enumerate_webhooks(self, app_id: str, app_name: str) -> List[Dict[str, Any]]:
        """Enumerate webhooks for an Amplify app"""
        webhooks = []

        try:
            paginator = self.amplify_client.get_paginator("list_webhooks")

            for page in paginator.paginate(appId=app_id):
                for webhook in page.get("webhooks", []):
                    webhook_data = {
                        "id": webhook.get("webhookId"),
                        "arn": webhook.get("webhookArn"),
                        "url": webhook.get("webhookUrl"),
                        "branch_name": webhook.get("branchName"),
                        "description": webhook.get("description", ""),
                        "create_time": webhook.get("createTime"),
                        "update_time": webhook.get("updateTime"),
                    }

                    webhooks.append(webhook_data)
                    self.data["webhooks"].append({"app_name": app_name, **webhook_data})

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating webhooks for {app_name}: {str(e)}"
            )

        return webhooks

    def _enumerate_backend_environments(
        self, app_id: str, app_name: str
    ) -> List[Dict[str, Any]]:
        """Enumerate backend environments for an Amplify app"""
        backend_envs = []

        try:
            paginator = self.amplify_client.get_paginator("list_backend_environments")

            for page in paginator.paginate(appId=app_id):
                for backend_env in page.get("backendEnvironments", []):
                    backend_env_name = backend_env.get("environmentName")

                    # Get detailed backend environment info
                    backend_details = self.amplify_client.get_backend_environment(
                        appId=app_id, environmentName=backend_env_name
                    )
                    backend_info = backend_details.get("backendEnvironment", {})

                    backend_data = {
                        "name": backend_env_name,
                        "arn": backend_info.get("backendEnvironmentArn"),
                        "stack_name": backend_info.get("stackName"),
                        "deployment_artifacts": backend_info.get("deploymentArtifacts"),
                        "create_time": backend_info.get("createTime"),
                        "update_time": backend_info.get("updateTime"),
                    }

                    backend_envs.append(backend_data)
                    self.data["backend_environments"].append(
                        {"app_name": app_name, **backend_data}
                    )

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating backend environments for {app_name}: {str(e)}"
            )

        return backend_envs

    def _display_app_panel(self, app_data: Dict[str, Any]):
        """Display Amplify app information in a formatted panel"""
        platform = app_data.get("platform", "WEB")
        auto_build = (
            "✓ Enabled" if app_data.get("enable_branch_auto_build") else "✗ Disabled"
        )
        basic_auth = (
            "🔒 Enabled" if app_data.get("enable_basic_auth") else "🔓 Disabled"
        )

        # Security status
        security_status = []
        if app_data.get("enable_basic_auth"):
            security_status.append("[green]✓ Basic Auth[/green]")

        if app_data.get("custom_headers"):
            security_status.append("[green]✓ Custom Headers[/green]")

        panel_content = (
            f"[bold]App ID:[/bold] {app_data.get('id')}\n"
            f"[bold]ARN:[/bold] {app_data.get('arn')}\n"
            f"[bold]Platform:[/bold] {platform}\n"
            f"[bold]Default Domain:[/bold] https://{app_data.get('default_domain')}\n\n"
            f"[bold cyan]Configuration:[/bold cyan]\n"
            f"  Repository: {app_data.get('repository', 'N/A')}\n"
            f"  Auto Build: {auto_build}\n"
            f"  Basic Auth: {basic_auth}\n"
        )

        if security_status:
            panel_content += f"  Security: {' | '.join(security_status)}\n"

        panel_content += "\n"

        if app_data.get("production_branch"):
            prod_branch = app_data.get("production_branch", {})
            panel_content += (
                f"[bold cyan]Production Branch:[/bold cyan]\n"
                f"  Name: {prod_branch.get('branchName', 'N/A')}\n"
                f"  Last Deploy: {prod_branch.get('lastDeployTime', 'N/A')}\n"
                f"  Status: {prod_branch.get('status', 'N/A')}\n\n"
            )

        if app_data.get("branches"):
            panel_content += f"[bold cyan]Branches:[/bold cyan] {len(app_data.get('branches', []))}\n"
            for branch in app_data.get("branches", [])[:5]:
                stage = branch.get("stage", "NONE")
                auto_build_status = "✓" if branch.get("enable_auto_build") else "✗"
                panel_content += (
                    f"  • {branch.get('name')} ({stage}) - "
                    f"Auto Build: {auto_build_status}\n"
                )
            if len(app_data.get("branches", [])) > 5:
                panel_content += (
                    f"  ... and {len(app_data.get('branches', [])) - 5} more\n"
                )
            panel_content += "\n"

        if app_data.get("domains"):
            panel_content += f"[bold cyan]Custom Domains:[/bold cyan] {len(app_data.get('domains', []))}\n"
            for domain in app_data.get("domains", []):
                status = domain.get("domain_status", "UNKNOWN")
                status_color = "green" if status == "AVAILABLE" else "yellow"
                panel_content += f"  • {domain.get('name')} - [{status_color}]{status}[/{status_color}]\n"
            panel_content += "\n"

        if app_data.get("webhooks"):
            panel_content += f"[bold cyan]Webhooks:[/bold cyan] {len(app_data.get('webhooks', []))}\n"
            for webhook in app_data.get("webhooks", [])[:3]:
                panel_content += f"  • {webhook.get('branch_name')} - {webhook.get('description', 'N/A')}\n"
            panel_content += "\n"

        if app_data.get("backend_environments"):
            panel_content += f"[bold cyan]Backend Environments:[/bold cyan] {len(app_data.get('backend_environments', []))}\n"
            for backend in app_data.get("backend_environments", []):
                panel_content += f"  • {backend.get('name')} - Stack: {backend.get('stack_name', 'N/A')}\n"
            panel_content += "\n"

        if app_data.get("environment_variables") and self.options.get("CHECK_ENV_VARS"):
            sensitive_count = sum(
                1
                for key in app_data.get("environment_variables", {}).keys()
                if any(
                    keyword in key.upper()
                    for keyword in ["PASSWORD", "SECRET", "KEY", "TOKEN", "API"]
                )
            )
            if sensitive_count > 0:
                panel_content += f"[bold cyan]Environment Variables:[/bold cyan] {len(app_data.get('environment_variables', {}))} "
                panel_content += (
                    f"([yellow]⚠[/yellow] {sensitive_count} potentially sensitive)\n\n"
                )

        iam_role_arn = app_data.get("iam_service_role_arn")
        if iam_role_arn:
            panel_content += (
                f"[bold cyan]IAM Role:[/bold cyan]\n  {iam_role_arn.split('/')[-1]}\n\n"
            )

        if app_data.get("tags"):
            panel_content += "[bold cyan]Tags:[/bold cyan]\n"
            for key, value in list(app_data.get("tags", {}).items())[:5]:
                panel_content += f"  • {key}: {value}\n"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{app_data.get('name')}[/bold]",
                expand=False,
            )
        )

    def _check_app_security(self, app_data: Dict[str, Any]) -> List[str]:
        """Check Amplify app for security issues."""
        findings = []
        app_name = app_data.get("name")

        if not app_data.get("enable_basic_auth"):
            prod_branch = app_data.get("production_branch", {})
            if prod_branch.get("branchName"):
                findings.append(f"Amplify app '{app_name}' basic auth disabled")

        if self.options.get("CHECK_ENV_VARS"):
            env_vars = app_data.get("environment_variables", {})
            for key in env_vars.keys():
                if any(
                    keyword in key.upper()
                    for keyword in ["PASSWORD", "SECRET", "KEY", "TOKEN", "API"]
                ):
                    findings.append(
                        f"Amplify app '{app_name}' sensitive env var: {key}"
                    )
                    self.data["sensitive_env_vars"].append(
                        {"app": app_name, "variable": key}
                    )

        if not app_data.get("custom_headers"):
            findings.append(f"Amplify app '{app_name}' missing security headers")

        if app_data.get("enable_auto_branch_creation") and not app_data.get(
            "auto_branch_creation_patterns"
        ):
            findings.append(
                f"Amplify app '{app_name}' auto branch creation without patterns"
            )

        for branch in app_data.get("branches", []):
            if branch.get("stage") == "PRODUCTION" and not branch.get(
                "enable_notification"
            ):
                findings.append(
                    f"Production branch '{branch.get('name')}' in '{app_name}' notifications disabled"
                )

        return findings

    def save_results(self) -> str:
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"amplify_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)

            # Create output directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare data for JSON serialization
            output_data = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "region": self.options.get("AWS_REGION"),
                    "total_apps": self.data["total_apps"],
                    "total_branches": self.data["total_branches"],
                    "total_domains": self.data["total_domains"],
                },
                "summary": {
                    "apps_with_auto_branch_creation": len(
                        self.data["apps_with_auto_branch_creation"]
                    ),
                    "apps_with_custom_domains": len(
                        self.data["apps_with_custom_domains"]
                    ),
                    "sensitive_env_vars": len(self.data["sensitive_env_vars"]),
                    "total_webhooks": len(self.data["webhooks"]),
                    "total_backend_environments": len(
                        self.data["backend_environments"]
                    ),
                    "security_findings": len(self.data["security_findings"]),
                },
                "apps": self.data["apps"],
                "branches": self.data["branches"],
                "domains": self.data["domains"],
                "webhooks": self.data["webhooks"],
                "backend_environments": self.data["backend_environments"],
                "security_findings": self.data["security_findings"],
                "sensitive_env_vars": self.data["sensitive_env_vars"],
            }

            save_json_results(output_data, output_path)
            console.print(f"\n[green]✓[/green] Results saved to: {output_file}")
            return output_file

        except (IOError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            return ""

    def run(self) -> Dict[str, Any]:
        """Execute Amplify enumeration"""

        panel = Panel(
            "[bold cyan]AWS Amplify Application Enumeration[/bold cyan]\n"
            f"Region: {self.options.get('AWS_REGION')}\n"
            "[dim]Collecting apps, branches, domains, webhooks, and deployment configuration[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize client
        if not self.initialize_client():
            return {"success": False, "error": "Failed to initialize Amplify client"}

        # Execute enumeration
        self.enumerate_apps()

        # Save results
        output_file = self.save_results()

        # Summary
        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(
            f"[bold]Applications:[/bold] {self.data['total_apps']} | "
            f"[bold]Branches:[/bold] {self.data['total_branches']} | "
            f"[bold]Domains:[/bold] {self.data['total_domains']}"
        )
        console.print(
            f"  [bold]Webhooks:[/bold] {len(self.data['webhooks'])} | "
            f"[bold]Backend Environments:[/bold] {len(self.data['backend_environments'])}"
        )

        if self.data["sensitive_env_vars"]:
            console.print(
                f"\n[yellow]⚠[/yellow] Sensitive Environment Variables: {len(self.data['sensitive_env_vars'])}"
            )
            for var in self.data["sensitive_env_vars"][:5]:
                console.print(f"  • {var.get('app')}: {var.get('variable')}")
            if len(self.data["sensitive_env_vars"]) > 5:
                console.print(
                    f"  ... and {len(self.data['sensitive_env_vars']) - 5} more"
                )

        if self.data["security_findings"]:
            console.print(
                f"\n[yellow]⚠[/yellow] Security Findings: {len(self.data['security_findings'])}"
            )
            for finding in self.data["security_findings"][:5]:
                console.print(f"  • {finding}")
            if len(self.data["security_findings"]) > 5:
                console.print(
                    f"  ... and {len(self.data['security_findings']) - 5} more"
                )

        return {
            "success": True,
            "output_file": output_file,
        }
