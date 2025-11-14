"""AWS Database Enumeration Module"""

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
    """AWS database enumeration including RDS, Aurora, DynamoDB, and ElastiCache."""

    NAME = "database_enumeration"
    DESCRIPTION = "AWS RDS and database service enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_RDS": True,
        "ENUMERATE_SNAPSHOTS": True,
        "ENUMERATE_DYNAMODB": True,
        "ENUMERATE_ELASTICACHE": True,
        "CHECK_PUBLIC_ACCESS": True,
        "OUTPUT_FILE": "database_enumeration_results.json",
    }

    REQUIRED_OPTIONS = ["AWS_REGION"]

    def __init__(self):
        super().__init__()
        self.rds_client = None
        self.dynamodb_client = None
        self.elasticache_client = None
        self.data = {
            "rds_instances": [],
            "aurora_clusters": [],
            "snapshots": [],
            "dynamodb_tables": [],
            "elasticache_clusters": [],
            "parameter_groups": [],
            "subnet_groups": [],
            "security_findings": [],
            "total_rds_instances": 0,
            "total_aurora_clusters": 0,
            "total_snapshots": 0,
            "total_dynamodb_tables": 0,
            "total_elasticache_clusters": 0,
            "public_databases": [],
            "unencrypted_databases": [],
            "public_snapshots": [],
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
        """Initialize AWS database clients."""
        try:
            session_kwargs = self._get_session_kwargs()

            session = boto3.Session(**session_kwargs)
            self.rds_client = session.client("rds")
            self.dynamodb_client = session.client("dynamodb")
            self.elasticache_client = session.client("elasticache")

            # Test connection
            self.rds_client.describe_db_instances(MaxRecords=1)
            console.print("[green]✓[/green] Successfully connected to AWS RDS")
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
            console.print(
                f"[red]✗[/red] Failed to initialize database clients: {str(e)}"
            )
            return False

    def enumerate_rds_instances(self):
        """Enumerate all RDS DB instances"""
        if not self.options.get("ENUMERATE_RDS"):
            return

        console.print("\n[bold cyan]═══ Enumerating RDS DB Instances ═══[/bold cyan]")

        try:
            paginator = self.rds_client.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db_instance in page.get("DBInstances", []):
                    db_id = db_instance.get("DBInstanceIdentifier")
                    console.print(f"\n[bold]Processing:[/bold] {db_id}")

                    # Get tags
                    tags = []
                    try:
                        tag_response = self.rds_client.list_tags_for_resource(
                            ResourceName=db_instance.get("DBInstanceArn")
                        )
                        tags = tag_response.get("TagList", [])
                    except Exception:
                        pass

                    instance_info = {
                        "identifier": db_id,
                        "arn": db_instance.get("DBInstanceArn"),
                        "engine": db_instance.get("Engine"),
                        "engine_version": db_instance.get("EngineVersion"),
                        "instance_class": db_instance.get("DBInstanceClass"),
                        "status": db_instance.get("DBInstanceStatus"),
                        "master_username": db_instance.get("MasterUsername"),
                        "endpoint": db_instance.get("Endpoint", {}).get("Address"),
                        "port": db_instance.get("Endpoint", {}).get("Port"),
                        "availability_zone": db_instance.get("AvailabilityZone"),
                        "multi_az": db_instance.get("MultiAZ"),
                        "publicly_accessible": db_instance.get("PubliclyAccessible"),
                        "storage_type": db_instance.get("StorageType"),
                        "allocated_storage": db_instance.get("AllocatedStorage"),
                        "storage_encrypted": db_instance.get("StorageEncrypted"),
                        "kms_key_id": db_instance.get("KmsKeyId"),
                        "vpc_security_groups": [
                            sg.get("VpcSecurityGroupId")
                            for sg in db_instance.get("VpcSecurityGroups", [])
                        ],
                        "db_subnet_group": db_instance.get("DBSubnetGroup", {}).get(
                            "DBSubnetGroupName"
                        ),
                        "parameter_group": db_instance.get("DBParameterGroups", [{}])[
                            0
                        ].get("DBParameterGroupName"),
                        "backup_retention_period": db_instance.get(
                            "BackupRetentionPeriod"
                        ),
                        "preferred_backup_window": db_instance.get(
                            "PreferredBackupWindow"
                        ),
                        "preferred_maintenance_window": db_instance.get(
                            "PreferredMaintenanceWindow"
                        ),
                        "latest_restorable_time": db_instance.get(
                            "LatestRestorableTime"
                        ),
                        "auto_minor_version_upgrade": db_instance.get(
                            "AutoMinorVersionUpgrade"
                        ),
                        "performance_insights_enabled": db_instance.get(
                            "PerformanceInsightsEnabled"
                        ),
                        "deletion_protection": db_instance.get("DeletionProtection"),
                        "iam_database_authentication_enabled": db_instance.get(
                            "IAMDatabaseAuthenticationEnabled"
                        ),
                        "enhanced_monitoring_arn": db_instance.get(
                            "EnhancedMonitoringResourceArn"
                        ),
                        "tags": tags,
                    }

                    # Check for security findings
                    findings = self._check_rds_security(instance_info)
                    instance_info["security_findings"] = findings
                    self.data["security_findings"].extend(findings)

                    # Track special configurations
                    if instance_info.get("publicly_accessible"):
                        self.data["public_databases"].append(db_id)

                    if not instance_info.get("storage_encrypted"):
                        self.data["unencrypted_databases"].append(db_id)

                    self.data["rds_instances"].append(instance_info)
                    self.data["total_rds_instances"] += 1

                    # Display instance panel
                    self._display_rds_panel(instance_info)

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_rds_instances']} RDS instances"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            console.print(
                f"[red]✗[/red] Error enumerating RDS instances: {error_code} - {error_msg}"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Unexpected error: {str(e)}")

    def _display_rds_panel(self, db_info: Dict[str, Any]):
        """Display RDS instance information in a formatted panel"""
        public_status = (
            "⚠️ Public" if db_info.get("publicly_accessible") else "✓ Private"
        )
        encryption_status = (
            "🔐 Encrypted" if db_info.get("storage_encrypted") else "🔓 Unencrypted"
        )
        multi_az_status = "✓ Multi-AZ" if db_info.get("multi_az") else "✗ Single-AZ"

        # Security status
        security_status = []
        if db_info.get("storage_encrypted"):
            security_status.append("[green]✓ Encrypted[/green]")
        else:
            security_status.append("[red]✗ Unencrypted[/red]")

        if not db_info.get("publicly_accessible"):
            security_status.append("[green]✓ Private[/green]")
        else:
            security_status.append("[red]⚠ Public[/red]")

        if db_info.get("deletion_protection"):
            security_status.append("[green]✓ Deletion Protected[/green]")

        panel_content = (
            f"[bold]ARN:[/bold] {db_info.get('arn', 'N/A')}\n"
            f"[bold]Engine:[/bold] {db_info.get('engine')} {db_info.get('engine_version')}\n"
            f"[bold]Instance Class:[/bold] {db_info.get('instance_class')}\n"
            f"[bold]Status:[/bold] {db_info.get('status')}\n\n"
            f"[bold cyan]Connectivity:[/bold cyan]\n"
            f"  Endpoint: {db_info.get('endpoint', 'N/A')}:{db_info.get('port', 'N/A')}\n"
            f"  Public Access: {public_status}\n"
            f"  Availability: {multi_az_status} ({db_info.get('availability_zone')})\n\n"
            f"[bold cyan]Storage:[/bold cyan]\n"
            f"  Type: {db_info.get('storage_type')} | "
            f"Size: {db_info.get('allocated_storage')} GB\n"
            f"  Encryption: {encryption_status}\n"
        )

        kms_key_id = db_info.get("kms_key_id")
        if kms_key_id:
            panel_content += f"  KMS Key: {kms_key_id.split('/')[-1]}\n"

        panel_content += (
            f"\n[bold cyan]Security:[/bold cyan]\n"
            f"  Status: {' | '.join(security_status)}\n"
            f"  VPC Security Groups: {len(db_info.get('vpc_security_groups', []))}\n"
            f"  IAM Auth: {'✓ Enabled' if db_info.get('iam_database_authentication_enabled') else '✗ Disabled'}\n"
            f"  Deletion Protection: {'✓ Enabled' if db_info.get('deletion_protection') else '✗ Disabled'}\n\n"
            f"[bold cyan]Backup:[/bold cyan]\n"
            f"  Retention: {db_info.get('backup_retention_period', 0)} days\n"
            f"  Window: {db_info.get('preferred_backup_window', 'N/A')}\n"
            f"  Latest Restorable: {db_info.get('latest_restorable_time', 'N/A')}\n\n"
            f"[bold cyan]Monitoring:[/bold cyan]\n"
            f"  Performance Insights: {'✓ Enabled' if db_info.get('performance_insights_enabled') else '✗ Disabled'}\n"
            f"  Enhanced Monitoring: {'✓ Enabled' if db_info.get('enhanced_monitoring_arn') else '✗ Disabled'}\n"
        )

        if db_info.get("tags"):
            panel_content += "\n[bold cyan]Tags:[/bold cyan]\n"
            for tag in db_info.get("tags", [])[:5]:
                panel_content += f"  • {tag.get('Key')}: {tag.get('Value')}\n"

        console.print(
            Panel(
                panel_content,
                title=f"[bold]{db_info.get('identifier')}[/bold]",
                expand=False,
            )
        )

    def _check_rds_security(self, db_info: Dict[str, Any]) -> List[str]:
        """Check RDS instance for security issues."""
        findings = []
        db_id = db_info.get("identifier")

        if db_info.get("publicly_accessible"):
            findings.append(f"RDS instance '{db_id}' is publicly accessible")

        if not db_info.get("storage_encrypted"):
            findings.append(f"RDS instance '{db_id}' storage encryption disabled")

        if db_info.get("backup_retention_period", 0) < 7:
            findings.append(f"RDS instance '{db_id}' backup retention < 7 days")

        if not db_info.get("deletion_protection"):
            findings.append(f"RDS instance '{db_id}' deletion protection disabled")

        if not db_info.get("multi_az"):
            findings.append(f"RDS instance '{db_id}' not Multi-AZ")

        if not db_info.get("iam_database_authentication_enabled"):
            findings.append(f"RDS instance '{db_id}' IAM auth disabled")

        if not db_info.get("performance_insights_enabled"):
            findings.append(f"RDS instance '{db_id}' Performance Insights disabled")

        return findings

    def enumerate_aurora_clusters(self):
        """Enumerate Aurora DB clusters"""
        if not self.options.get("ENUMERATE_RDS"):
            return

        console.print("\n[bold cyan]═══ Enumerating Aurora DB Clusters ═══[/bold cyan]")

        try:
            paginator = self.rds_client.get_paginator("describe_db_clusters")

            for page in paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    cluster_id = cluster.get("DBClusterIdentifier")
                    console.print(f"\n[bold]Processing:[/bold] {cluster_id}")

                    cluster_info = {
                        "identifier": cluster_id,
                        "arn": cluster.get("DBClusterArn"),
                        "engine": cluster.get("Engine"),
                        "engine_version": cluster.get("EngineVersion"),
                        "engine_mode": cluster.get("EngineMode"),
                        "status": cluster.get("Status"),
                        "endpoint": cluster.get("Endpoint"),
                        "reader_endpoint": cluster.get("ReaderEndpoint"),
                        "port": cluster.get("Port"),
                        "master_username": cluster.get("MasterUsername"),
                        "multi_az": cluster.get("MultiAZ"),
                        "storage_encrypted": cluster.get("StorageEncrypted"),
                        "kms_key_id": cluster.get("KmsKeyId"),
                        "vpc_security_groups": [
                            sg.get("VpcSecurityGroupId")
                            for sg in cluster.get("VpcSecurityGroups", [])
                        ],
                        "db_subnet_group": cluster.get("DBSubnetGroup"),
                        "backup_retention_period": cluster.get("BackupRetentionPeriod"),
                        "preferred_backup_window": cluster.get("PreferredBackupWindow"),
                        "deletion_protection": cluster.get("DeletionProtection"),
                        "iam_database_authentication_enabled": cluster.get(
                            "IAMDatabaseAuthenticationEnabled"
                        ),
                        "cluster_members": [
                            member.get("DBInstanceIdentifier")
                            for member in cluster.get("DBClusterMembers", [])
                        ],
                        "enabled_cloudwatch_logs_exports": cluster.get(
                            "EnabledCloudwatchLogsExports", []
                        ),
                    }

                    self.data["aurora_clusters"].append(cluster_info)
                    self.data["total_aurora_clusters"] += 1

                    # Display cluster info
                    console.print(
                        f"  [bold]{cluster_id}[/bold] - {cluster_info.get('engine')} {cluster_info.get('engine_version')} "
                        f"({cluster_info.get('engine_mode', 'provisioned')}) - "
                        f"Members: {len(cluster_info.get('cluster_members', []))}"
                    )

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_aurora_clusters']} Aurora clusters"
            )

        except Exception as e:
            console.print(
                f"[yellow]⚠[/yellow] Error enumerating Aurora clusters: {str(e)}"
            )

    def enumerate_snapshots(self):
        """Enumerate RDS snapshots"""
        if not self.options.get("ENUMERATE_SNAPSHOTS"):
            return

        console.print("\n[bold cyan]═══ Enumerating RDS Snapshots ═══[/bold cyan]")

        try:
            paginator = self.rds_client.get_paginator("describe_db_snapshots")

            for page in paginator.paginate():
                for snapshot in page.get("DBSnapshots", []):
                    snapshot_id = snapshot.get("DBSnapshotIdentifier")

                    # Check if snapshot is public
                    is_public = False
                    try:
                        attrs = self.rds_client.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snapshot_id
                        )
                        for attr in attrs.get("DBSnapshotAttributesResult", {}).get(
                            "DBSnapshotAttributes", []
                        ):
                            if attr.get(
                                "AttributeName"
                            ) == "restore" and "all" in attr.get("AttributeValues", []):
                                is_public = True
                                self.data["public_snapshots"].append(snapshot_id)
                    except Exception:
                        pass

                    snapshot_info = {
                        "identifier": snapshot_id,
                        "arn": snapshot.get("DBSnapshotArn"),
                        "db_instance_identifier": snapshot.get("DBInstanceIdentifier"),
                        "snapshot_type": snapshot.get("SnapshotType"),
                        "status": snapshot.get("Status"),
                        "engine": snapshot.get("Engine"),
                        "engine_version": snapshot.get("EngineVersion"),
                        "allocated_storage": snapshot.get("AllocatedStorage"),
                        "snapshot_create_time": snapshot.get("SnapshotCreateTime"),
                        "encrypted": snapshot.get("Encrypted"),
                        "kms_key_id": snapshot.get("KmsKeyId"),
                        "is_public": is_public,
                        "availability_zone": snapshot.get("AvailabilityZone"),
                    }

                    self.data["snapshots"].append(snapshot_info)
                    self.data["total_snapshots"] += 1

            console.print(
                f"[green]✓[/green] Found {self.data['total_snapshots']} RDS snapshots"
            )
            if self.data["public_snapshots"]:
                console.print(
                    f"[red]⚠[/red] {len(self.data['public_snapshots'])} public snapshots found!"
                )

        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Error enumerating snapshots: {str(e)}")

    def enumerate_dynamodb(self):
        """Enumerate DynamoDB tables"""
        if not self.options.get("ENUMERATE_DYNAMODB"):
            return

        console.print("\n[bold cyan]═══ Enumerating DynamoDB Tables ═══[/bold cyan]")

        try:
            paginator = self.dynamodb_client.get_paginator("list_tables")

            for page in paginator.paginate():
                for table_name in page.get("TableNames", []):
                    # Get table details
                    table_desc = self.dynamodb_client.describe_table(
                        TableName=table_name
                    )
                    table = table_desc.get("Table", {})

                    # Get continuous backups info
                    backup_info = {}
                    try:
                        backup_desc = self.dynamodb_client.describe_continuous_backups(
                            TableName=table_name
                        )
                        backup_info = backup_desc.get(
                            "ContinuousBackupsDescription", {}
                        )
                    except Exception:
                        pass

                    table_info = {
                        "name": table_name,
                        "arn": table.get("TableArn"),
                        "status": table.get("TableStatus"),
                        "item_count": table.get("ItemCount"),
                        "table_size_bytes": table.get("TableSizeBytes"),
                        "creation_date_time": table.get("CreationDateTime"),
                        "billing_mode": table.get("BillingModeSummary", {}).get(
                            "BillingMode", "PROVISIONED"
                        ),
                        "sse_description": table.get("SSEDescription", {}),
                        "encryption_type": table.get("SSEDescription", {}).get(
                            "SSEType"
                        ),
                        "stream_enabled": table.get("StreamSpecification", {}).get(
                            "StreamEnabled", False
                        ),
                        "point_in_time_recovery": backup_info.get(
                            "PointInTimeRecoveryDescription", {}
                        ).get("PointInTimeRecoveryStatus")
                        == "ENABLED",
                        "global_secondary_indexes": len(
                            table.get("GlobalSecondaryIndexes", [])
                        ),
                        "local_secondary_indexes": len(
                            table.get("LocalSecondaryIndexes", [])
                        ),
                    }

                    self.data["dynamodb_tables"].append(table_info)
                    self.data["total_dynamodb_tables"] += 1

                    encryption_status = (
                        "🔐 Encrypted"
                        if table_info.get("encryption_type")
                        else "🔓 Default"
                    )
                    pitr_status = (
                        "✓ Enabled"
                        if table_info.get("point_in_time_recovery")
                        else "✗ Disabled"
                    )

                    console.print(
                        f"  [bold]{table_name}[/bold] - {table_info.get('status')} | "
                        f"Items: {table_info.get('item_count', 0):,} | "
                        f"Size: {table_info.get('table_size_bytes', 0) / 1024 / 1024:.2f} MB | "
                        f"Encryption: {encryption_status} | PITR: {pitr_status}"
                    )

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_dynamodb_tables']} DynamoDB tables"
            )

        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Error enumerating DynamoDB: {str(e)}")

    def enumerate_elasticache(self):
        """Enumerate ElastiCache clusters"""
        if not self.options.get("ENUMERATE_ELASTICACHE"):
            return

        console.print(
            "\n[bold cyan]═══ Enumerating ElastiCache Clusters ═══[/bold cyan]"
        )

        try:
            # Redis clusters
            redis_paginator = self.elasticache_client.get_paginator(
                "describe_cache_clusters"
            )

            for page in redis_paginator.paginate(ShowCacheNodeInfo=True):
                for cluster in page.get("CacheClusters", []):
                    cluster_id = cluster.get("CacheClusterId")

                    cluster_info = {
                        "identifier": cluster_id,
                        "arn": cluster.get("ARN"),
                        "engine": cluster.get("Engine"),
                        "engine_version": cluster.get("EngineVersion"),
                        "cache_node_type": cluster.get("CacheNodeType"),
                        "status": cluster.get("CacheClusterStatus"),
                        "num_cache_nodes": cluster.get("NumCacheNodes"),
                        "preferred_availability_zone": cluster.get(
                            "PreferredAvailabilityZone"
                        ),
                        "cache_subnet_group": cluster.get("CacheSubnetGroupName"),
                        "security_groups": [
                            sg.get("SecurityGroupId")
                            for sg in cluster.get("SecurityGroups", [])
                        ],
                        "at_rest_encryption_enabled": cluster.get(
                            "AtRestEncryptionEnabled"
                        ),
                        "transit_encryption_enabled": cluster.get(
                            "TransitEncryptionEnabled"
                        ),
                        "auth_token_enabled": cluster.get("AuthTokenEnabled"),
                        "snapshot_retention_limit": cluster.get(
                            "SnapshotRetentionLimit"
                        ),
                    }

                    self.data["elasticache_clusters"].append(cluster_info)
                    self.data["total_elasticache_clusters"] += 1

                    encryption_status = (
                        "🔐 Encrypted"
                        if cluster_info.get("at_rest_encryption_enabled")
                        else "🔓 Unencrypted"
                    )

                    console.print(
                        f"  [bold]{cluster_id}[/bold] - {cluster_info.get('engine')} {cluster_info.get('engine_version')} | "
                        f"Nodes: {cluster_info.get('num_cache_nodes')} | "
                        f"{encryption_status}"
                    )

            console.print(
                f"\n[green]✓[/green] Found {self.data['total_elasticache_clusters']} ElastiCache clusters"
            )

        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Error enumerating ElastiCache: {str(e)}")

    def save_results(self) -> str:
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"database_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)

            # Create output directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare data for JSON serialization
            output_data = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "region": self.options.get("AWS_REGION"),
                    "total_rds_instances": self.data["total_rds_instances"],
                    "total_aurora_clusters": self.data["total_aurora_clusters"],
                    "total_snapshots": self.data["total_snapshots"],
                    "total_dynamodb_tables": self.data["total_dynamodb_tables"],
                    "total_elasticache_clusters": self.data[
                        "total_elasticache_clusters"
                    ],
                },
                "summary": {
                    "public_databases": len(self.data["public_databases"]),
                    "unencrypted_databases": len(self.data["unencrypted_databases"]),
                    "public_snapshots": len(self.data["public_snapshots"]),
                    "security_findings": len(self.data["security_findings"]),
                },
                "rds_instances": self.data["rds_instances"],
                "aurora_clusters": self.data["aurora_clusters"],
                "snapshots": self.data["snapshots"],
                "dynamodb_tables": self.data["dynamodb_tables"],
                "elasticache_clusters": self.data["elasticache_clusters"],
                "security_findings": self.data["security_findings"],
            }

            save_json_results(output_data, output_path)
            console.print(f"\n[green]✓[/green] Results saved to: {output_file}")
            return output_file

        except (IOError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            return ""

    def run(self) -> Dict[str, Any]:
        """Execute database enumeration"""

        panel = Panel(
            "[bold cyan]AWS RDS & Database Service Enumeration[/bold cyan]\n"
            f"Region: {self.options.get('AWS_REGION')}\n"
            "[dim]Collecting RDS, Aurora, DynamoDB, ElastiCache, and security configuration[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize client
        if not self.initialize_client():
            return {
                "success": False,
                "error": "Failed to initialize database clients",
                "data": self.data,
            }

        # Execute enumeration
        self.enumerate_rds_instances()
        self.enumerate_aurora_clusters()
        self.enumerate_snapshots()
        self.enumerate_dynamodb()
        self.enumerate_elasticache()

        # Save results
        output_file = self.save_results()

        # Summary
        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(
            f"[bold]RDS Instances:[/bold] {self.data['total_rds_instances']} | "
            f"[bold]Aurora Clusters:[/bold] {self.data['total_aurora_clusters']} | "
            f"[bold]Snapshots:[/bold] {self.data['total_snapshots']}"
        )
        console.print(
            f"[bold]DynamoDB Tables:[/bold] {self.data['total_dynamodb_tables']} | "
            f"[bold]ElastiCache:[/bold] {self.data['total_elasticache_clusters']}"
        )
        console.print(
            f"  [red]⚠[/red] Public Databases: {len(self.data['public_databases'])} | "
            f"[yellow]⚠[/yellow] Unencrypted: {len(self.data['unencrypted_databases'])} | "
            f"[red]⚠[/red] Public Snapshots: {len(self.data['public_snapshots'])}"
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
