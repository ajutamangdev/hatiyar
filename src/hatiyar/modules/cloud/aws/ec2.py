"""AWS EC2 Enumeration Module"""

from typing import Dict, Any, List
import boto3
from datetime import datetime
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from rich.console import Console
from rich.panel import Panel
from hatiyar.core.module_base import ModuleBase, ModuleType
from hatiyar.utils.output import save_json_results

console = Console()


class Module(ModuleBase):
    """AWS EC2 and VPC enumeration including instances, security groups, volumes, and networking resources."""

    NAME = "ec2_enumeration"
    DESCRIPTION = "AWS EC2, VPC, and networking resource enumeration"
    MODULE_TYPE = ModuleType.ENUMERATION
    CATEGORY = "cloud"
    PLATFORM = ["aws"]

    OPTIONS = {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "",
        "ACCESS_KEY": "",
        "SECRET_KEY": "",
        "SESSION_TOKEN": "",
        "ENUMERATE_INSTANCES": True,
        "OUTPUT_FILE": "ec2_enumeration_results.json",
    }

    REQUIRED_OPTIONS = ["AWS_REGION"]

    def __init__(self):
        super().__init__()
        self.ec2_client = None
        self.ec2_resource = None
        self.ssm_client = None
        self.elbv2_client = None
        self.elb_client = None  # For Classic Load Balancers
        self.autoscaling_client = None
        self.data = {
            "instances": [],  # Will contain all associated resources per instance
            "vpcs": [],
            "subnets": [],
            "amis": [],
            "snapshots": [],
            "key_pairs": [],
            "network_acls": [],
            "route_tables": [],
            "internet_gateways": [],
            "nat_gateways": [],
            "vpc_endpoints": [],
            "load_balancers": [],
            "auto_scaling_groups": [],
        }
        # Temporary storage for resource lookups
        self._security_groups = {}
        self._elastic_ips = {}
        self._volumes = {}
        self._ssm_status = {}
        self._network_interfaces = {}
        self._vpcs = {}
        self._subnets = {}
        self._load_balancers = {}
        self._target_groups = {}
        self._auto_scaling_groups = {}

    def initialize_client(self) -> bool:
        """Initialize AWS EC2 client with multiple credential options"""
        try:
            session_kwargs = {
                "region_name": self.options.get("AWS_REGION", "us-east-1")
            }

            if self.options.get("AWS_PROFILE"):
                session_kwargs["profile_name"] = self.options["AWS_PROFILE"]
                console.print(
                    f"[cyan]→[/cyan] Using AWS profile: {self.options['AWS_PROFILE']}"
                )

            elif self.options.get("ACCESS_KEY") and self.options.get("SECRET_KEY"):
                session_kwargs["aws_access_key_id"] = self.options["ACCESS_KEY"]
                session_kwargs["aws_secret_access_key"] = self.options["SECRET_KEY"]
                if self.options.get("SESSION_TOKEN"):
                    session_kwargs["aws_session_token"] = self.options["SESSION_TOKEN"]
                console.print("[cyan]→[/cyan] Using provided credentials")

            else:
                console.print("[cyan]→[/cyan] Using default AWS credentials")

            session = boto3.Session(**session_kwargs)
            self.ec2_client = session.client("ec2")
            self.ec2_resource = session.resource("ec2")
            self.ssm_client = session.client("ssm")
            self.elbv2_client = session.client("elbv2")  # ALB/NLB
            self.elb_client = session.client("elb")  # Classic LB
            self.autoscaling_client = session.client("autoscaling")

            # Test credentials
            self.ec2_client.describe_regions()
            console.print(
                f"[green]✓[/green] Connected to AWS EC2 in region: {self.options['AWS_REGION']}"
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
            if e.response["Error"]["Code"] == "UnauthorizedOperation":
                console.print(
                    "[red]✗[/red] Credentials valid but not authorized for EC2 operations"
                )
            else:
                console.print(
                    f"[red]✗[/red] AWS Error: {e.response['Error']['Message']}"
                )
            return False
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize EC2 client: {str(e)}")
            return False

    def _collect_security_groups(self):
        """Collect all security groups for lookup"""
        try:
            paginator = self.ec2_client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    self._security_groups[sg["GroupId"]] = {
                        "group_id": sg["GroupId"],
                        "group_name": sg.get("GroupName", "N/A"),
                        "description": sg.get("Description", ""),
                        "vpc_id": sg.get("VpcId", "N/A"),
                        "inbound_rules": self._format_sg_rules(
                            sg.get("IpPermissions", [])
                        ),
                        "outbound_rules": self._format_sg_rules(
                            sg.get("IpPermissionsEgress", [])
                        ),
                    }
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect security groups: {str(e)}[/yellow]"
            )

    def _collect_elastic_ips(self):
        """Collect all Elastic IPs for lookup by instance"""
        try:
            response = self.ec2_client.describe_addresses()
            for address in response.get("Addresses", []):
                instance_id = address.get("InstanceId")
                if instance_id:
                    self._elastic_ips[instance_id] = {
                        "public_ip": address.get("PublicIp", "N/A"),
                        "allocation_id": address.get("AllocationId", "N/A"),
                        "association_id": address.get("AssociationId", "N/A"),
                        "domain": address.get("Domain", "N/A"),
                    }
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect Elastic IPs: {str(e)}[/yellow]"
            )

    def _collect_volumes(self):
        """Collect all volumes for lookup by instance"""
        try:
            paginator = self.ec2_client.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    attachments = volume.get("Attachments", [])
                    for attachment in attachments:
                        instance_id = attachment.get("InstanceId")
                        if instance_id:
                            if instance_id not in self._volumes:
                                self._volumes[instance_id] = []
                            self._volumes[instance_id].append(
                                {
                                    "volume_id": volume["VolumeId"],
                                    "size_gb": volume["Size"],
                                    "volume_type": volume.get("VolumeType", "N/A"),
                                    "encrypted": volume.get("Encrypted", False),
                                    "state": volume["State"],
                                    "device": attachment.get("Device", "N/A"),
                                    "iops": volume.get("Iops", "N/A"),
                                    "throughput": volume.get("Throughput", "N/A"),
                                }
                            )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect volumes: {str(e)}[/yellow]"
            )

    def _collect_ssm_status(self):
        """Collect SSM agent status for lookup by instance"""
        try:
            response = self.ssm_client.describe_instance_information()
            for instance in response.get("InstanceInformationList", []):
                instance_id = instance.get("InstanceId")
                if instance_id:
                    self._ssm_status[instance_id] = {
                        "ping_status": instance.get("PingStatus", "N/A"),
                        "agent_version": instance.get("AgentVersion", "N/A"),
                        "platform_name": instance.get("PlatformName", "N/A"),
                        "platform_version": instance.get("PlatformVersion", "N/A"),
                        "last_ping": str(instance.get("LastPingDateTime", "N/A")),
                    }
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect SSM status: {str(e)}[/yellow]"
            )

    def _format_sg_rules(self, rules: List[Dict]) -> List[str]:
        """Format security group rules into readable strings"""
        formatted = []
        for rule in rules:
            protocol = rule.get("IpProtocol", "")
            if protocol == "-1":
                protocol = "All"
            elif protocol == "6":
                protocol = "TCP"
            elif protocol == "17":
                protocol = "UDP"

            from_port = rule.get("FromPort", "All")
            to_port = rule.get("ToPort", "All")
            port_range = (
                f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
            )

            sources = []
            for ip_range in rule.get("IpRanges", []):
                sources.append(ip_range.get("CidrIp", ""))
            for ipv6_range in rule.get("Ipv6Ranges", []):
                sources.append(ipv6_range.get("CidrIpv6", ""))
            for sg_ref in rule.get("UserIdGroupPairs", []):
                sources.append(f"sg:{sg_ref.get('GroupId', '')}")

            source_str = ", ".join(sources) if sources else "N/A"
            formatted.append(f"{protocol}:{port_range} from {source_str}")

        return formatted

    def _collect_network_interfaces(self):
        """Collect all network interfaces for lookup by instance"""
        try:
            paginator = self.ec2_client.get_paginator("describe_network_interfaces")
            for page in paginator.paginate():
                for eni in page.get("NetworkInterfaces", []):
                    attachment = eni.get("Attachment", {})
                    instance_id = attachment.get("InstanceId")
                    if instance_id:
                        if instance_id not in self._network_interfaces:
                            self._network_interfaces[instance_id] = []
                        self._network_interfaces[instance_id].append(
                            {
                                "interface_id": eni["NetworkInterfaceId"],
                                "status": eni.get("Status", "N/A"),
                                "mac_address": eni.get("MacAddress", "N/A"),
                                "private_ip": eni.get("PrivateIpAddress", "N/A"),
                                "subnet_id": eni.get("SubnetId", "N/A"),
                                "vpc_id": eni.get("VpcId", "N/A"),
                                "description": eni.get("Description", ""),
                                "source_dest_check": eni.get("SourceDestCheck", True),
                                "attachment_id": attachment.get("AttachmentId", "N/A"),
                                "device_index": attachment.get("DeviceIndex", 0),
                            }
                        )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect network interfaces: {str(e)}[/yellow]"
            )

    def _collect_vpcs(self):
        """Collect all VPCs for lookup"""
        try:
            response = self.ec2_client.describe_vpcs()
            for vpc in response.get("Vpcs", []):
                vpc_id = vpc["VpcId"]
                name = "N/A"
                for tag in vpc.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]

                self._vpcs[vpc_id] = {
                    "vpc_id": vpc_id,
                    "name": name,
                    "cidr_block": vpc.get("CidrBlock", "N/A"),
                    "state": vpc.get("State", "N/A"),
                    "is_default": vpc.get("IsDefault", False),
                    "dhcp_options_id": vpc.get("DhcpOptionsId", "N/A"),
                    "instance_tenancy": vpc.get("InstanceTenancy", "default"),
                }
                self.data["vpcs"].append(self._vpcs[vpc_id])
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect VPCs: {str(e)}[/yellow]"
            )

    def _collect_subnets(self):
        """Collect all subnets for lookup"""
        try:
            response = self.ec2_client.describe_subnets()
            for subnet in response.get("Subnets", []):
                subnet_id = subnet["SubnetId"]
                name = "N/A"
                for tag in subnet.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]

                self._subnets[subnet_id] = {
                    "subnet_id": subnet_id,
                    "name": name,
                    "vpc_id": subnet.get("VpcId", "N/A"),
                    "cidr_block": subnet.get("CidrBlock", "N/A"),
                    "availability_zone": subnet.get("AvailabilityZone", "N/A"),
                    "available_ips": subnet.get("AvailableIpAddressCount", 0),
                    "map_public_ip": subnet.get("MapPublicIpOnLaunch", False),
                    "state": subnet.get("State", "N/A"),
                }
                self.data["subnets"].append(self._subnets[subnet_id])
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect subnets: {str(e)}[/yellow]"
            )

    def _collect_amis(self):
        """Collect AMIs owned by the account"""
        try:
            response = self.ec2_client.describe_images(Owners=["self"])
            for ami in response.get("Images", []):
                name = ami.get("Name", "N/A")
                self.data["amis"].append(
                    {
                        "ami_id": ami["ImageId"],
                        "name": name,
                        "description": ami.get("Description", ""),
                        "state": ami.get("State", "N/A"),
                        "architecture": ami.get("Architecture", "N/A"),
                        "platform": ami.get("Platform", "Linux/Unix"),
                        "root_device_type": ami.get("RootDeviceType", "N/A"),
                        "virtualization_type": ami.get("VirtualizationType", "N/A"),
                        "creation_date": ami.get("CreationDate", "N/A"),
                        "public": ami.get("Public", False),
                    }
                )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect AMIs: {str(e)}[/yellow]"
            )

    def _collect_snapshots(self):
        """Collect EBS snapshots owned by the account"""
        try:
            paginator = self.ec2_client.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snapshot in page.get("Snapshots", []):
                    description = snapshot.get("Description", "")
                    self.data["snapshots"].append(
                        {
                            "snapshot_id": snapshot["SnapshotId"],
                            "volume_id": snapshot.get("VolumeId", "N/A"),
                            "description": description,
                            "state": snapshot.get("State", "N/A"),
                            "progress": snapshot.get("Progress", "N/A"),
                            "start_time": str(snapshot.get("StartTime", "N/A")),
                            "volume_size": snapshot.get("VolumeSize", 0),
                            "encrypted": snapshot.get("Encrypted", False),
                        }
                    )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect snapshots: {str(e)}[/yellow]"
            )

    def _collect_key_pairs(self):
        """Collect SSH key pairs"""
        try:
            response = self.ec2_client.describe_key_pairs()
            for kp in response.get("KeyPairs", []):
                self.data["key_pairs"].append(
                    {
                        "key_name": kp["KeyName"],
                        "key_fingerprint": kp.get("KeyFingerprint", "N/A"),
                        "key_type": kp.get("KeyType", "rsa"),
                        "create_time": str(kp.get("CreateTime", "N/A")),
                    }
                )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect key pairs: {str(e)}[/yellow]"
            )

    def _collect_network_acls(self):
        """Collect Network ACLs"""
        try:
            response = self.ec2_client.describe_network_acls()
            for nacl in response.get("NetworkAcls", []):
                name = "N/A"
                for tag in nacl.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]

                self.data["network_acls"].append(
                    {
                        "nacl_id": nacl["NetworkAclId"],
                        "name": name,
                        "vpc_id": nacl.get("VpcId", "N/A"),
                        "is_default": nacl.get("IsDefault", False),
                        "associations": [
                            assoc.get("SubnetId", "N/A")
                            for assoc in nacl.get("Associations", [])
                        ],
                        "inbound_rules": len(
                            [
                                e
                                for e in nacl.get("Entries", [])
                                if not e.get("Egress", False)
                            ]
                        ),
                        "outbound_rules": len(
                            [
                                e
                                for e in nacl.get("Entries", [])
                                if e.get("Egress", False)
                            ]
                        ),
                    }
                )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect Network ACLs: {str(e)}[/yellow]"
            )

    def _collect_route_tables(self):
        """Collect Route Tables"""
        try:
            response = self.ec2_client.describe_route_tables()
            for rt in response.get("RouteTables", []):
                name = "N/A"
                for tag in rt.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]

                routes = []
                for route in rt.get("Routes", []):
                    destination = route.get("DestinationCidrBlock") or route.get(
                        "DestinationIpv6CidrBlock", "N/A"
                    )
                    target = (
                        route.get("GatewayId")
                        or route.get("NatGatewayId")
                        or route.get("NetworkInterfaceId")
                        or route.get("VpcPeeringConnectionId")
                        or "local"
                    )
                    routes.append(f"{destination} → {target}")

                self.data["route_tables"].append(
                    {
                        "route_table_id": rt["RouteTableId"],
                        "name": name,
                        "vpc_id": rt.get("VpcId", "N/A"),
                        "associations": [
                            assoc.get("SubnetId", "Main")
                            for assoc in rt.get("Associations", [])
                        ],
                        "routes": routes,
                    }
                )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect route tables: {str(e)}[/yellow]"
            )

    def _collect_internet_gateways(self):
        """Collect Internet Gateways"""
        try:
            response = self.ec2_client.describe_internet_gateways()
            for igw in response.get("InternetGateways", []):
                name = "N/A"
                for tag in igw.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]

                self.data["internet_gateways"].append(
                    {
                        "igw_id": igw["InternetGatewayId"],
                        "name": name,
                        "attachments": [
                            att.get("VpcId", "N/A")
                            for att in igw.get("Attachments", [])
                        ],
                        "state": igw.get("Attachments", [{}])[0].get("State", "N/A")
                        if igw.get("Attachments")
                        else "detached",
                    }
                )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect internet gateways: {str(e)}[/yellow]"
            )

    def _collect_nat_gateways(self):
        """Collect NAT Gateways"""
        try:
            paginator = self.ec2_client.get_paginator("describe_nat_gateways")
            for page in paginator.paginate():
                for ngw in page.get("NatGateways", []):
                    name = "N/A"
                    for tag in ngw.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]

                    nat_ips = [
                        addr.get("PublicIp", "N/A")
                        for addr in ngw.get("NatGatewayAddresses", [])
                    ]

                    self.data["nat_gateways"].append(
                        {
                            "nat_gateway_id": ngw["NatGatewayId"],
                            "name": name,
                            "vpc_id": ngw.get("VpcId", "N/A"),
                            "subnet_id": ngw.get("SubnetId", "N/A"),
                            "state": ngw.get("State", "N/A"),
                            "public_ips": nat_ips,
                            "connectivity_type": ngw.get("ConnectivityType", "public"),
                        }
                    )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect NAT gateways: {str(e)}[/yellow]"
            )

    def _collect_vpc_endpoints(self):
        """Collect VPC Endpoints"""
        try:
            response = self.ec2_client.describe_vpc_endpoints()
            for endpoint in response.get("VpcEndpoints", []):
                name = "N/A"
                for tag in endpoint.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]

                self.data["vpc_endpoints"].append(
                    {
                        "endpoint_id": endpoint["VpcEndpointId"],
                        "name": name,
                        "vpc_id": endpoint.get("VpcId", "N/A"),
                        "service_name": endpoint.get("ServiceName", "N/A"),
                        "endpoint_type": endpoint.get("VpcEndpointType", "N/A"),
                        "state": endpoint.get("State", "N/A"),
                        "route_table_ids": endpoint.get("RouteTableIds", []),
                        "subnet_ids": endpoint.get("SubnetIds", []),
                    }
                )
        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect VPC endpoints: {str(e)}[/yellow]"
            )

    def _collect_load_balancers(self):
        """Collect Application/Network Load Balancers and Classic Load Balancers"""
        try:
            # ALB/NLB
            response = self.elbv2_client.describe_load_balancers()
            for lb in response.get("LoadBalancers", []):
                lb_arn = lb["LoadBalancerArn"]

                # Get target groups
                tg_response = self.elbv2_client.describe_target_groups(
                    LoadBalancerArn=lb_arn
                )
                target_groups = []
                for tg in tg_response.get("TargetGroups", []):
                    # Get targets (instances)
                    tg_arn = tg["TargetGroupArn"]
                    self._target_groups[tg_arn] = tg

                    targets_response = self.elbv2_client.describe_target_health(
                        TargetGroupArn=tg_arn
                    )
                    targets = []
                    for target in targets_response.get("TargetHealthDescriptions", []):
                        target_id = target["Target"]["Id"]
                        targets.append(
                            {
                                "instance_id": target_id,
                                "port": target["Target"].get("Port", "N/A"),
                                "health_state": target.get("TargetHealth", {}).get(
                                    "State", "N/A"
                                ),
                            }
                        )

                    target_groups.append(
                        {
                            "name": tg["TargetGroupName"],
                            "arn": tg_arn,
                            "protocol": tg.get("Protocol", "N/A"),
                            "port": tg.get("Port", "N/A"),
                            "vpc_id": tg.get("VpcId", "N/A"),
                            "health_check_path": tg.get("HealthCheckPath", "N/A"),
                            "targets": targets,
                        }
                    )

                lb_data = {
                    "name": lb["LoadBalancerName"],
                    "arn": lb_arn,
                    "type": lb.get("Type", "application"),
                    "scheme": lb.get("Scheme", "internet-facing"),
                    "dns_name": lb.get("DNSName", "N/A"),
                    "vpc_id": lb.get("VpcId", "N/A"),
                    "availability_zones": [
                        az.get("ZoneName", "N/A")
                        for az in lb.get("AvailabilityZones", [])
                    ],
                    "security_groups": lb.get("SecurityGroups", []),
                    "state": lb.get("State", {}).get("Code", "N/A"),
                    "target_groups": target_groups,
                    "lb_version": "v2",
                }
                self.data["load_balancers"].append(lb_data)
                self._load_balancers[lb["LoadBalancerName"]] = lb_data

        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect ALB/NLB: {str(e)}[/yellow]"
            )

        try:
            # Classic Load Balancers
            response = self.elb_client.describe_load_balancers()
            for lb in response.get("LoadBalancerDescriptions", []):
                instances = [inst["InstanceId"] for inst in lb.get("Instances", [])]

                lb_data = {
                    "name": lb["LoadBalancerName"],
                    "type": "classic",
                    "scheme": lb.get("Scheme", "internet-facing"),
                    "dns_name": lb.get("DNSName", "N/A"),
                    "vpc_id": lb.get("VPCId", "N/A"),
                    "availability_zones": lb.get("AvailabilityZones", []),
                    "security_groups": lb.get("SecurityGroups", []),
                    "instances": instances,
                    "lb_version": "classic",
                }
                self.data["load_balancers"].append(lb_data)
                self._load_balancers[lb["LoadBalancerName"]] = lb_data

        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect Classic LBs: {str(e)}[/yellow]"
            )

    def _collect_auto_scaling_groups(self):
        """Collect Auto Scaling Groups"""
        try:
            paginator = self.autoscaling_client.get_paginator(
                "describe_auto_scaling_groups"
            )
            for page in paginator.paginate():
                for asg in page.get("AutoScalingGroups", []):
                    asg_name = asg["AutoScalingGroupName"]
                    instances = [
                        inst["InstanceId"] for inst in asg.get("Instances", [])
                    ]

                    asg_data = {
                        "name": asg_name,
                        "arn": asg.get("AutoScalingGroupARN", "N/A"),
                        "launch_config": asg.get("LaunchConfigurationName", "N/A"),
                        "launch_template": asg.get("LaunchTemplate", {}).get(
                            "LaunchTemplateName", "N/A"
                        ),
                        "min_size": asg.get("MinSize", 0),
                        "max_size": asg.get("MaxSize", 0),
                        "desired_capacity": asg.get("DesiredCapacity", 0),
                        "availability_zones": asg.get("AvailabilityZones", []),
                        "load_balancers": asg.get("LoadBalancerNames", []),
                        "target_group_arns": asg.get("TargetGroupARNs", []),
                        "vpc_zone_ids": asg.get("VPCZoneIdentifier", "").split(",")
                        if asg.get("VPCZoneIdentifier")
                        else [],
                        "health_check_type": asg.get("HealthCheckType", "EC2"),
                        "instances": instances,
                        "status": asg.get("Status", "N/A"),
                    }
                    self.data["auto_scaling_groups"].append(asg_data)
                    self._auto_scaling_groups[asg_name] = asg_data

        except Exception as e:
            console.print(
                f"[yellow]⚠ Warning: Could not collect Auto Scaling Groups: {str(e)}[/yellow]"
            )

    def enumerate_instances(self):
        """Enumerate all EC2 instances with associated resources"""
        if not self.options.get("ENUMERATE_INSTANCES"):
            return

        console.print("\n[bold cyan]═══ Enumerating AWS Resources ═══[/bold cyan]")
        console.print(
            "[dim]Collecting: Security Groups, Elastic IPs, Volumes, Network Interfaces, VPCs, Subnets, AMIs, Snapshots, Key Pairs, Network ACLs, Route Tables, Gateways, VPC Endpoints, Load Balancers, Auto Scaling Groups...[/dim]"
        )

        # Collect all resources first for association
        self._collect_security_groups()
        self._collect_elastic_ips()
        self._collect_volumes()
        self._collect_ssm_status()
        self._collect_network_interfaces()
        self._collect_vpcs()
        self._collect_subnets()
        self._collect_amis()
        self._collect_snapshots()
        self._collect_key_pairs()
        self._collect_network_acls()
        self._collect_route_tables()
        self._collect_internet_gateways()
        self._collect_nat_gateways()
        self._collect_vpc_endpoints()
        self._collect_load_balancers()
        self._collect_auto_scaling_groups()

        console.print(
            "\n[bold cyan]═══ EC2 Instances with Associated Resources ═══[/bold cyan]"
        )

        try:
            paginator = self.ec2_client.get_paginator("describe_instances")
            instance_count = 0

            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_count += 1

                        instance_id = instance["InstanceId"]
                        instance_type = instance["InstanceType"]
                        state = instance["State"]["Name"]
                        public_ip = instance.get("PublicIpAddress", "N/A")
                        private_ip = instance.get("PrivateIpAddress", "N/A")
                        vpc_id = instance.get("VpcId", "N/A")
                        subnet_id = instance.get("SubnetId", "N/A")
                        az = instance.get("Placement", {}).get(
                            "AvailabilityZone", "N/A"
                        )

                        # Get instance name from tags
                        name = "N/A"
                        tags_dict = {}
                        for tag in instance.get("Tags", []):
                            tags_dict[tag["Key"]] = tag["Value"]
                            if tag["Key"] == "Name":
                                name = tag["Value"]

                        # Get security groups with details
                        sg_ids = [
                            sg["GroupId"] for sg in instance.get("SecurityGroups", [])
                        ]
                        security_groups = []
                        for sg_id in sg_ids:
                            if sg_id in self._security_groups:
                                security_groups.append(self._security_groups[sg_id])

                        # Get associated Elastic IP
                        elastic_ip = self._elastic_ips.get(instance_id)

                        # Get attached volumes
                        volumes = self._volumes.get(instance_id, [])

                        # Get SSM status
                        ssm_status = self._ssm_status.get(instance_id)

                        # Get network interfaces
                        network_interfaces = self._network_interfaces.get(
                            instance_id, []
                        )

                        # Find load balancers containing this instance
                        associated_lbs = []
                        for lb_name, lb_data in self._load_balancers.items():
                            if lb_data.get("lb_version") == "classic":
                                if instance_id in lb_data.get("instances", []):
                                    associated_lbs.append(lb_data)
                            else:
                                for tg in lb_data.get("target_groups", []):
                                    if any(
                                        t["instance_id"] == instance_id
                                        for t in tg.get("targets", [])
                                    ):
                                        associated_lbs.append(lb_data)
                                        break

                        # Find ASG containing this instance
                        associated_asg = None
                        for asg_name, asg_data in self._auto_scaling_groups.items():
                            if instance_id in asg_data.get("instances", []):
                                associated_asg = asg_data
                                break

                        # Build comprehensive display
                        state_color = (
                            "green"
                            if state == "running"
                            else "yellow"
                            if state == "stopped"
                            else "red"
                        )

                        details = f"""[bold]Instance ID:[/bold] {instance_id}
[bold]Name:[/bold] {name}
[bold]Type:[/bold] {instance_type}
[bold]State:[/bold] [{state_color}]{state}[/{state_color}]
[bold]Platform:[/bold] {instance.get("Platform", "Linux/Unix")}

[bold cyan]Network Configuration:[/bold cyan]
  • VPC: {vpc_id}
  • Subnet: {subnet_id}
  • Availability Zone: {az}
  • Private IP: {private_ip}
  • Public IP: {public_ip}"""

                        # Add Elastic IP info if exists
                        if elastic_ip:
                            details += f"""
  • [bold]Elastic IP:[/bold] {elastic_ip["public_ip"]}
    - Allocation ID: {elastic_ip["allocation_id"]}
    - Domain: {elastic_ip["domain"]}"""

                        # Add Security Groups
                        details += f"\n\n[bold cyan]Security Groups ({len(security_groups)}):[/bold cyan]"
                        if security_groups:
                            for sg in security_groups:
                                details += (
                                    f"\n  • {sg['group_name']} ({sg['group_id']})"
                                )
                                details += f"\n    Description: {sg['description']}"
                                if sg["inbound_rules"]:
                                    details += f"\n    Inbound: {len(sg['inbound_rules'])} rule(s)"
                                    for rule in sg["inbound_rules"][:3]:  # Show first 3
                                        details += f"\n      - {rule}"
                                    if len(sg["inbound_rules"]) > 3:
                                        details += f"\n      ... and {len(sg['inbound_rules']) - 3} more"
                        else:
                            details += "\n  • No security groups"

                        # Add Volumes
                        details += (
                            f"\n\n[bold cyan]EBS Volumes ({len(volumes)}):[/bold cyan]"
                        )
                        if volumes:
                            for vol in volumes:
                                encryption = (
                                    "[green]Encrypted[/green]"
                                    if vol["encrypted"]
                                    else "[red]Unencrypted[/red]"
                                )
                                details += f"\n  • {vol['volume_id']} - {vol['size_gb']} GB {vol['volume_type']}"
                                details += f"\n    Device: {vol['device']} | {encryption} | State: {vol['state']}"
                                if vol["iops"] != "N/A":
                                    details += f" | IOPS: {vol['iops']}"
                        else:
                            details += "\n  • No volumes attached"

                        # Add SSM Status
                        details += "\n\n[bold cyan]Systems Manager:[/bold cyan]"
                        if ssm_status:
                            status_color = (
                                "green"
                                if ssm_status["ping_status"] == "Online"
                                else "red"
                            )
                            details += f"\n  • Status: [{status_color}]{ssm_status['ping_status']}[/{status_color}]"
                            details += (
                                f"\n  • Agent Version: {ssm_status['agent_version']}"
                            )
                            details += f"\n  • Platform: {ssm_status['platform_name']} {ssm_status['platform_version']}"
                            details += f"\n  • Last Ping: {ssm_status['last_ping']}"
                        else:
                            details += "\n  • SSM Agent: Not Installed/Not Responding"

                        # Add Network Interfaces
                        details += f"\n\n[bold cyan]Network Interfaces ({len(network_interfaces)}):[/bold cyan]"
                        if network_interfaces:
                            for eni in network_interfaces:
                                details += f"\n  • {eni['interface_id']} (eth{eni['device_index']})"
                                details += f"\n    MAC: {eni['mac_address']} | IP: {eni['private_ip']}"
                                details += f"\n    Status: {eni['status']} | Source/Dest Check: {eni['source_dest_check']}"
                        else:
                            details += "\n  • No additional network interfaces"

                        # Add Load Balancers
                        if associated_lbs:
                            details += f"\n\n[bold cyan]Load Balancers ({len(associated_lbs)}):[/bold cyan]"
                            for lb in associated_lbs:
                                lb_type = lb["type"].upper()
                                details += f"\n  • {lb['name']} ({lb_type})"
                                details += f"\n    DNS: {lb['dns_name']}"
                                details += f"\n    Scheme: {lb['scheme']} | State: {lb.get('state', 'active')}"
                                if lb.get("lb_version") != "classic":
                                    for tg in lb.get("target_groups", []):
                                        matching_targets = [
                                            t
                                            for t in tg.get("targets", [])
                                            if t["instance_id"] == instance_id
                                        ]
                                        if matching_targets:
                                            target = matching_targets[0]
                                            details += f"\n    Target Group: {tg['name']} | Health: {target['health_state']}"

                        # Add Auto Scaling Group
                        if associated_asg:
                            details += "\n\n[bold cyan]Auto Scaling Group:[/bold cyan]"
                            details += f"\n  • Name: {associated_asg['name']}"
                            details += f"\n  • Capacity: Min={associated_asg['min_size']}, Desired={associated_asg['desired_capacity']}, Max={associated_asg['max_size']}"
                            details += f"\n  • Health Check: {associated_asg['health_check_type']}"
                            if associated_asg.get("load_balancers"):
                                details += f"\n  • LBs: {', '.join(associated_asg['load_balancers'][:3])}"

                        # Add Metadata
                        details += "\n\n[bold cyan]Instance Metadata:[/bold cyan]"
                        details += f"\n  • Key Pair: {instance.get('KeyName', 'N/A')}"
                        details += f"\n  • IAM Role: {instance.get('IamInstanceProfile', {}).get('Arn', 'N/A')}"
                        details += f"\n  • Monitoring: {instance.get('Monitoring', {}).get('State', 'disabled')}"
                        details += (
                            f"\n  • Launch Time: {instance.get('LaunchTime', 'N/A')}"
                        )
                        details += (
                            f"\n  • Architecture: {instance.get('Architecture', 'N/A')}"
                        )
                        details += f"\n  • Root Device: {instance.get('RootDeviceType', 'N/A')}"

                        # Add Tags if present
                        if tags_dict:
                            details += "\n\n[bold cyan]Tags:[/bold cyan]"
                            for k, v in list(tags_dict.items())[
                                :5
                            ]:  # Show first 5 tags
                                details += f"\n  • {k}: {v}"
                            if len(tags_dict) > 5:
                                details += f"\n  ... and {len(tags_dict) - 5} more tags"

                        # Display comprehensive panel
                        console.print(
                            Panel(
                                details,
                                title=f"[bold]Instance {instance_count}: {name}[/bold]",
                                border_style="cyan",
                                expand=False,
                            )
                        )

                        # Store comprehensive data
                        instance_data = {
                            "instance_id": instance_id,
                            "name": name,
                            "type": instance_type,
                            "state": state,
                            "platform": instance.get("Platform", "Linux/Unix"),
                            "ami_id": instance.get("ImageId", "N/A"),
                            "network": {
                                "vpc_id": vpc_id,
                                "subnet_id": subnet_id,
                                "availability_zone": az,
                                "private_ip": private_ip,
                                "public_ip": public_ip,
                                "elastic_ip": elastic_ip,
                            },
                            "security_groups": security_groups,
                            "volumes": volumes,
                            "ssm_status": ssm_status,
                            "network_interfaces": network_interfaces,
                            "load_balancers": [
                                {
                                    "name": lb["name"],
                                    "type": lb["type"],
                                    "dns": lb["dns_name"],
                                }
                                for lb in associated_lbs
                            ],
                            "auto_scaling_group": {
                                "name": associated_asg["name"],
                                "desired_capacity": associated_asg["desired_capacity"],
                            }
                            if associated_asg
                            else None,
                            "metadata": {
                                "key_name": instance.get("KeyName", "N/A"),
                                "iam_role": instance.get("IamInstanceProfile", {}).get(
                                    "Arn", "N/A"
                                ),
                                "monitoring": instance.get("Monitoring", {}).get(
                                    "State", "disabled"
                                ),
                                "launch_time": str(instance.get("LaunchTime", "N/A")),
                                "architecture": instance.get("Architecture", "N/A"),
                                "root_device_type": instance.get(
                                    "RootDeviceType", "N/A"
                                ),
                                "hypervisor": instance.get("Hypervisor", "N/A"),
                            },
                            "tags": tags_dict,
                        }
                        self.data["instances"].append(instance_data)

            console.print(
                f"\n[green]✓ Enumerated {instance_count} EC2 instance(s) with all associated resources[/green]"
            )

        except ClientError as e:
            console.print(
                f"[red]✗ Error enumerating instances: {e.response['Error']['Message']}[/red]"
            )
        except Exception as e:
            console.print(f"[red]✗ Unexpected error: {str(e)}[/red]")

    def save_results(self):
        """Save enumeration results to JSON file"""
        output_file = self.options.get("OUTPUT_FILE")

        # If no output file specified, generate default filename with timestamp
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ec2_enumeration_{timestamp}.json"

        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Add metadata
            output_data = {
                "metadata": {
                    "scan_time": datetime.now().isoformat(),
                    "region": self.options.get("AWS_REGION"),
                    "module": self.NAME,
                    "version": self.VERSION,
                },
                "data": self.data,
                "summary": {
                    "total_instances": len(self.data["instances"]),
                    "total_security_groups": len(self._security_groups),
                    "total_volumes": sum(
                        len(self._volumes.get(inst["instance_id"], []))
                        for inst in self.data["instances"]
                    ),
                    "total_elastic_ips": len(
                        [eip for eip in self._elastic_ips.values()]
                    ),
                    "instances_with_ssm": len(
                        [
                            inst
                            for inst in self.data["instances"]
                            if inst.get("ssm_status")
                        ]
                    ),
                    "total_vpcs": len(self.data["vpcs"]),
                    "total_subnets": len(self.data["subnets"]),
                    "total_amis": len(self.data["amis"]),
                    "total_snapshots": len(self.data["snapshots"]),
                    "total_key_pairs": len(self.data["key_pairs"]),
                    "total_network_acls": len(self.data["network_acls"]),
                    "total_route_tables": len(self.data["route_tables"]),
                    "total_internet_gateways": len(self.data["internet_gateways"]),
                    "total_nat_gateways": len(self.data["nat_gateways"]),
                    "total_vpc_endpoints": len(self.data["vpc_endpoints"]),
                    "total_load_balancers": len(self.data["load_balancers"]),
                    "total_auto_scaling_groups": len(self.data["auto_scaling_groups"]),
                },
            }

            save_json_results(output_data, output_path)
            console.print(
                f"\n[green]✓ Results saved to: {output_path.absolute()}[/green]"
            )
            return str(output_path.absolute())

        except (IOError, ValueError) as e:
            console.print(f"[red]✗ {e}[/red]")
            return None

    def run(self) -> Dict[str, Any]:
        """Execute EC2 enumeration"""

        panel = Panel(
            "[bold cyan]AWS EC2 Instance-Centric Resource Enumeration[/bold cyan]\n"
            f"Region: {self.options.get('AWS_REGION')}\n"
            "[dim]Collecting instances with associated EIPs, Security Groups, Volumes, and SSM status[/dim]",
            expand=False,
        )
        console.print(panel)

        # Initialize client
        if not self.initialize_client():
            return {
                "success": False,
                "status": "failed",
                "error": "Failed to initialize AWS client",
            }

        # Execute instance-centric enumeration
        self.enumerate_instances()

        # Save results to JSON file
        output_file = self.save_results()

        # Summary
        total_sg = len(self._security_groups)
        total_volumes = sum(len(vols) for vols in self._volumes.values())
        total_eips = len(self._elastic_ips)
        instances_with_ssm = len(self._ssm_status)

        console.print("\n[bold green]═══ Enumeration Complete ═══[/bold green]")
        console.print(
            f"[bold]Compute:[/bold] {len(self.data['instances'])} Instances, "
            f"{len(self.data['auto_scaling_groups'])} ASGs, "
            f"{len(self.data['load_balancers'])} LBs | "
            f"[bold]Network:[/bold] {len(self.data['vpcs'])} VPCs, "
            f"{len(self.data['subnets'])} Subnets, "
            f"{total_sg} SGs, "
            f"{total_eips} EIPs | "
            f"[bold]Storage:[/bold] {total_volumes} Volumes, "
            f"{len(self.data['snapshots'])} Snapshots, "
            f"{len(self.data['amis'])} AMIs"
        )

        return {
            "success": True,
            "status": "completed",
            "message": f"Enumeration complete. Results saved to {output_file}",
            "output_file": output_file,
            "summary": {
                "compute": {
                    "total_instances": len(self.data["instances"]),
                    "auto_scaling_groups": len(self.data["auto_scaling_groups"]),
                    "load_balancers": len(self.data["load_balancers"]),
                },
                "network": {
                    "vpcs": len(self.data["vpcs"]),
                    "subnets": len(self.data["subnets"]),
                    "security_groups": total_sg,
                    "network_acls": len(self.data["network_acls"]),
                    "elastic_ips": total_eips,
                    "internet_gateways": len(self.data["internet_gateways"]),
                    "nat_gateways": len(self.data["nat_gateways"]),
                    "vpc_endpoints": len(self.data["vpc_endpoints"]),
                },
                "storage": {
                    "volumes": total_volumes,
                    "snapshots": len(self.data["snapshots"]),
                    "amis": len(self.data["amis"]),
                },
                "other": {
                    "key_pairs": len(self.data["key_pairs"]),
                    "instances_with_ssm": instances_with_ssm,
                },
            },
        }
