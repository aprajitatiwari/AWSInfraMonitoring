import boto3
import json
import os
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, BotoCoreError
from collections import defaultdict

# Setup Logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Clients
s3 = boto3.client("s3")
config = boto3.client("config")
ce = boto3.client("ce")

bucket_name = "aprajita-change-and-impact-summarizer-for-aws-inventory-bucket"

# AWS Service to Resource Type Mapping
SERVICE_RESOURCE_MAPPING = {
    "Amazon Elastic Compute Cloud - Compute": ["AWS::EC2::Instance"],
    "Amazon Elastic Block Store": ["AWS::EC2::Volume"],
    "Amazon Virtual Private Cloud": ["AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::InternetGateway", 
                                   "AWS::EC2::RouteTable", "AWS::EC2::NetworkAcl", "AWS::EC2::NatGateway"],
    "AWS Lambda": ["AWS::Lambda::Function"],
    "Amazon Elastic Container Service": ["AWS::ECS::Cluster", "AWS::ECS::Service"],
    "Amazon Elastic Kubernetes Service": ["AWS::EKS::Cluster"],
    "Amazon Simple Storage Service": ["AWS::S3::Bucket"],
    "Amazon Elastic File System": ["AWS::EFS::FileSystem"],
    "Amazon FSx": ["AWS::FSx::FileSystem"],
    "Amazon DynamoDB": ["AWS::DynamoDB::Table"],
    "Amazon Relational Database Service": ["AWS::RDS::DBInstance", "AWS::RDS::DBCluster"],
    "Amazon ElastiCache": ["AWS::ElastiCache::CacheCluster", "AWS::ElastiCache::ReplicationGroup"],
    "Amazon Redshift": ["AWS::Redshift::Cluster"],
    "Amazon CloudFront": ["AWS::CloudFront::Distribution"],
    "Elastic Load Balancing": ["AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer"],
    "Amazon Route 53": ["AWS::Route53::HostedZone"],
    "Amazon API Gateway": ["AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api"],
    "Amazon Simple Notification Service": ["AWS::SNS::Topic"],
    "Amazon Simple Queue Service": ["AWS::SQS::Queue"],
    "Amazon EventBridge": ["AWS::Events::Rule"],
    "AWS Step Functions": ["AWS::StepFunctions::StateMachine"],
    "Amazon Kinesis": ["AWS::Kinesis::Stream"],
    "Amazon Kinesis Firehose": ["AWS::KinesisFirehose::DeliveryStream"],
    "AWS Glue": ["AWS::Glue::Job", "AWS::Glue::Database"],
    "AWS Key Management Service": ["AWS::KMS::Key"],
    "AWS Secrets Manager": ["AWS::SecretsManager::Secret"],
    "AWS Systems Manager": ["AWS::SSM::Parameter"],
    "AWS Certificate Manager": ["AWS::CertificateManager::Certificate"],
    "Amazon CloudWatch": ["AWS::CloudWatch::Alarm"],
    "Amazon CloudWatch Logs": ["AWS::Logs::LogGroup"],
    "AWS CloudTrail": ["AWS::CloudTrail::Trail"],
    "AWS Config": ["AWS::Config::ConfigRule"],
    "AWS CodeCommit": ["AWS::CodeCommit::Repository"],
    "AWS CodeBuild": ["AWS::CodeBuild::Project"],
    "AWS CodePipeline": ["AWS::CodePipeline::Pipeline"],
    "Amazon SageMaker": ["AWS::SageMaker::NotebookInstance", "AWS::SageMaker::Model"]
}

# Comprehensive Resource Types (excluding IAM roles)
COMPREHENSIVE_RESOURCE_TYPES = [
    "AWS::EC2::Instance", "AWS::EC2::Volume", "AWS::EC2::SecurityGroup", "AWS::EC2::NetworkInterface",
    "AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::InternetGateway", "AWS::EC2::RouteTable",
    "AWS::EC2::NetworkAcl", "AWS::EC2::KeyPair", "AWS::EC2::EIP", "AWS::EC2::NatGateway",
    "AWS::Lambda::Function", "AWS::ECS::Cluster", "AWS::ECS::Service", "AWS::EKS::Cluster",
    "AWS::S3::Bucket", "AWS::EFS::FileSystem", "AWS::FSx::FileSystem",
    "AWS::DynamoDB::Table", "AWS::RDS::DBInstance", "AWS::RDS::DBCluster",
    "AWS::ElastiCache::CacheCluster", "AWS::ElastiCache::ReplicationGroup", "AWS::Redshift::Cluster",
    "AWS::CloudFront::Distribution", "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::Route53::HostedZone", "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api",
    "AWS::SNS::Topic", "AWS::SQS::Queue", "AWS::Events::Rule", "AWS::StepFunctions::StateMachine",
    "AWS::Kinesis::Stream", "AWS::KinesisFirehose::DeliveryStream", "AWS::Glue::Job", "AWS::Glue::Database",
    "AWS::KMS::Key", "AWS::SecretsManager::Secret", "AWS::SSM::Parameter", "AWS::CertificateManager::Certificate",
    "AWS::CloudWatch::Alarm", "AWS::Logs::LogGroup", "AWS::CloudTrail::Trail", "AWS::Config::ConfigRule",
    "AWS::CodeCommit::Repository", "AWS::CodeBuild::Project", "AWS::CodePipeline::Pipeline",
    "AWS::SageMaker::NotebookInstance", "AWS::SageMaker::Model"
]

def datetime_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def get_all_supported_resource_types():
    try:
        response = config.list_discovered_resource_counts()
        supported_types = [item['resourceType'] for item in response.get('resourceCounts', [])]
        supported_types = [rt for rt in supported_types if rt != "AWS::IAM::Role"]
        logger.info(f"Found {len(supported_types)} supported resource types (excluding IAM roles)")
        return supported_types
    except Exception as e:
        logger.warning(f"Could not get supported resource types, using comprehensive list: {str(e)}")
        return [rt for rt in COMPREHENSIVE_RESOURCE_TYPES if rt != "AWS::IAM::Role"]

def check_config_recording_status():
    try:
        recorders = config.describe_configuration_recorders()
        if not recorders.get('ConfigurationRecorders'):
            logger.warning("No AWS Config recorders found")
            return False

        recorder_status = config.describe_configuration_recorder_status()
        for status in recorder_status.get('ConfigurationRecordersStatus', []):
            if not status.get('recording', False):
                logger.warning(f"Config recorder {status.get('name')} is not recording")
                return False

        logger.info("AWS Config is properly configured and recording")
        return True
    except Exception as e:
        logger.error(f"Error checking Config status: {str(e)}")
        return False

def discover_resources_with_fallback(resource_types):
    all_resources = []
    successful_types = []
    failed_types = []
    resources_by_service = defaultdict(list)

    for res_type in resource_types:
        logger.info(f"Scanning resource type: {res_type}")
        resources_found = 0

        try:
            paginator = config.get_paginator("list_discovered_resources")
            for page in paginator.paginate(resourceType=res_type):
                for resource in page["resourceIdentifiers"]:
                    resource_id = resource["resourceId"]
                    try:
                        history = config.get_resource_config_history(
                            resourceType=res_type,
                            resourceId=resource_id,
                            limit=1
                        )

                        if history["configurationItems"]:
                            item = history["configurationItems"][0]
                            capture_time = item.get("configurationItemCaptureTime", "")
                            if isinstance(capture_time, datetime):
                                capture_time = capture_time.isoformat()

                            name = (
                                item.get("resourceName") or 
                                item.get("tags", {}).get("Name", "") or
                                resource_id
                            )

                            resource_entry = {
                                "ResourceType": res_type,
                                "ResourceId": resource_id,
                                "Region": os.environ.get('AWS_REGION', 'unknown'),
                                "ResourceName": name,
                                "CaptureTime": capture_time,
                                "ARN": item.get("arn", ""),
                                "Tags": item.get("tags", {}),
                                "AvailabilityZone": item.get("availabilityZone", ""),
                                "Status": item.get("configurationItemStatus", ""),
                                "ResourceCreationTime": item.get("resourceCreationTime", "")
                            }

                            all_resources.append(resource_entry)
                            
                            # Group by service for cost mapping
                            service_name = get_service_from_resource_type(res_type)
                            if service_name:
                                resources_by_service[service_name].append(resource_entry)
                            
                            resources_found += 1

                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ResourceNotDiscoveredException':
                            logger.debug(f"Resource not discovered: {resource_id}")
                        else:
                            logger.warning(f"Error getting config for {resource_id}: {str(e)}")
                    except Exception as e:
                        logger.warning(f"Unexpected error for {resource_id}: {str(e)}")

            if resources_found > 0:
                successful_types.append(res_type)
                logger.info(f"Found {resources_found} resources for {res_type}")
            else:
                logger.info(f"No resources found for {res_type}")

        except ClientError as e:
            logger.error(f"Error scanning {res_type}: {str(e)}")
            failed_types.append(res_type)
        except Exception as e:
            logger.error(f"Unexpected error scanning {res_type}: {str(e)}")
            failed_types.append(res_type)

    logger.info(f"Summary: {len(successful_types)} successful, {len(failed_types)} failed resource types")
    logger.info(f"Total resources discovered: {len(all_resources)}")

    return all_resources, successful_types, failed_types, resources_by_service

def get_service_from_resource_type(resource_type):
    """Map resource type to AWS service name for cost correlation"""
    for service, resource_types in SERVICE_RESOURCE_MAPPING.items():
        if resource_type in resource_types:
            return service
    return None

def get_cost_data(cost_start_date, cost_end_date):
    """Fetch cost data and organize by service"""
    try:
        logger.info(f"Fetching cost data from {cost_start_date} to {cost_end_date}")
        cost_response = ce.get_cost_and_usage(
            TimePeriod={
                "Start": cost_start_date.strftime("%Y-%m-%d"),
                "End": cost_end_date.strftime("%Y-%m-%d")
            },
            Granularity="DAILY",
            Metrics=["UnblendedCost", "BlendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}]
        )
        
        # Process cost data by service
        cost_by_service = {}
        for result in cost_response.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                service_name = group['Keys'][0]
                unblended_cost = float(group['Metrics']['UnblendedCost']['Amount'])
                blended_cost = float(group['Metrics']['BlendedCost']['Amount'])
                
                cost_by_service[service_name] = {
                    "unblended_cost": round(unblended_cost, 4),
                    "blended_cost": round(blended_cost, 4),
                    "currency": group['Metrics']['UnblendedCost']['Unit']
                }
        
        return cost_response, cost_by_service
    except Exception as e:
        logger.error(f"Error fetching cost data: {str(e)}")
        return None, {}

def merge_resources_with_costs(resources_by_service, cost_by_service):
    """Create merged inventory with cost information"""
    merged_inventory = []
    total_cost_summary = {
        "total_unblended_cost": 0.0,
        "total_blended_cost": 0.0,
        "currency": "USD"
    }
    
    # Create service-wise inventory with costs
    for service_name, resources in resources_by_service.items():
        cost_info = cost_by_service.get(service_name, {
            "unblended_cost": 0.0,
            "blended_cost": 0.0,
            "currency": "USD"
        })
        
        # Calculate per-resource cost estimate (if there are multiple resources)
        resource_count = len(resources)
        per_resource_cost = 0.0
        if resource_count > 0 and cost_info["unblended_cost"] > 0:
            per_resource_cost = round(cost_info["unblended_cost"] / resource_count, 4)
        
        service_entry = {
            "service_name": service_name,
            "total_service_cost": cost_info,
            "resource_count": resource_count,
            "estimated_cost_per_resource": per_resource_cost,
            "resources": resources
        }
        
        merged_inventory.append(service_entry)
        
        # Add to total
        total_cost_summary["total_unblended_cost"] += cost_info["unblended_cost"]
        total_cost_summary["total_blended_cost"] += cost_info["blended_cost"]
    
    # Round totals
    total_cost_summary["total_unblended_cost"] = round(total_cost_summary["total_unblended_cost"], 4)
    total_cost_summary["total_blended_cost"] = round(total_cost_summary["total_blended_cost"], 4)
    
    # Sort by cost (highest first)
    merged_inventory.sort(key=lambda x: x["total_service_cost"]["unblended_cost"], reverse=True)
    
    return merged_inventory, total_cost_summary

def cleanup_old_reports(date_folder_prefix):
    """Clean up reports older than 30 days"""
    try:
        cutoff_date = datetime.now() - timedelta(days=30)
        
        paginator = s3.get_paginator('list_objects_v2')
        
        objects_to_delete = []
        for page in paginator.paginate(Bucket=bucket_name, Prefix="Input_Folder/"):
            if 'Contents' in page:
                for obj in page['Contents']:
                    key = obj['Key']
                    try:
                        date_part = key.split('/')[1]
                        if len(date_part) == 10 and date_part.count('-') == 2:
                            folder_date = datetime.strptime(date_part, '%Y-%m-%d')
                            if folder_date < cutoff_date:
                                objects_to_delete.append({'Key': key})
                    except (IndexError, ValueError):
                        continue
        
        if objects_to_delete:
            logger.info(f"Deleting {len(objects_to_delete)} old report files")
            for i in range(0, len(objects_to_delete), 1000):
                batch = objects_to_delete[i:i+1000]
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': batch}
                )
            logger.info(f"Cleanup completed: removed {len(objects_to_delete)} old files")
        else:
            logger.info("No old files to cleanup")
            
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")

def lambda_handler(event, context):
    current_date = datetime.now()
    date_str = current_date.strftime('%Y-%m-%d')
    timestamp_str = current_date.strftime('%Y-%m-%d_%H-%M-%S')
    
    date_folder = f"Input_Folder/{date_str}/"
    region = os.environ.get('AWS_REGION', 'unknown')

    logger.info(f"Generating merged inventory and cost report for date: {date_str} in region {region}")

    cleanup_old_reports(date_folder)

    if not check_config_recording_status():
        logger.warning("AWS Config may not be properly configured. Results may be incomplete.")

    use_comprehensive = event.get("use_comprehensive_scan", False)
    if use_comprehensive:
        logger.info("Using comprehensive resource type list")
        resource_types = [rt for rt in COMPREHENSIVE_RESOURCE_TYPES if rt != "AWS::IAM::Role"]
    else:
        logger.info("Getting supported resource types from AWS Config")
        resource_types = get_all_supported_resource_types()

    logger.info(f"Will scan {len(resource_types)} resource types")

    # Discover resources grouped by service
    all_resources, successful_types, failed_types, resources_by_service = discover_resources_with_fallback(resource_types)

    # Get cost data for the same day as inventory (previous day to ensure data availability)
    # Both inventory and cost will represent the same date period
    cost_date = (current_date - timedelta(days=1)).date()  # Use yesterday for both
    cost_start_date = cost_date
    cost_end_date = cost_date + timedelta(days=1)  # Cost Explorer needs end date to be next day
    
    cost_response, cost_by_service = get_cost_data(cost_start_date, cost_end_date)
    
    # Merge resources with cost data
    merged_inventory, total_cost_summary = merge_resources_with_costs(resources_by_service, cost_by_service)

    # Create comprehensive merged report
    try:
        merged_report = {
            "metadata": {
                "report_type": "merged_inventory_and_cost",
                "report_date": date_str,  # The actual date both datasets represent
                "snapshot_timestamp": current_date.isoformat(),  # When the snapshot was taken
                "cost_period_start": cost_start_date.strftime("%Y-%m-%d"),
                "cost_period_end": cost_start_date.strftime("%Y-%m-%d"),  # Same day for perfect alignment
                "region": region,
                "total_resources": len(all_resources),
                "services_with_resources": len(merged_inventory),
                "successful_resource_types": len(successful_types),
                "failed_resource_types": len(failed_types)
            },
            "cost_summary": total_cost_summary,
            "service_inventory": merged_inventory,
            "raw_cost_data": cost_response if cost_response else {},
            "discovery_summary": {
                "successful_types": successful_types,
                "failed_types": failed_types
            }
        }

        # Save merged report
        merged_key = f"{date_folder}merged_inventory_cost_{timestamp_str}.json"
        s3.put_object(
            Bucket=bucket_name,
            Key=merged_key,
            Body=json.dumps(merged_report, indent=2, default=datetime_serializer),
            ContentType='application/json'
        )
        logger.info(f"Merged inventory and cost report saved to {merged_key}")

        # Also save individual files for backward compatibility
        config_key = f"{date_folder}config_snapshot_{timestamp_str}.json"
        config_data = {
            "metadata": {
                "report_date": date_str,  # The actual date this data represents
                "snapshot_timestamp": current_date.isoformat(),  # When snapshot was taken
                "region": region,
                "total_resources": len(all_resources),
                "successful_resource_types": len(successful_types),
                "failed_resource_types": len(failed_types)
            },
            "resources": all_resources
        }
        
        s3.put_object(
            Bucket=bucket_name,
            Key=config_key,
            Body=json.dumps(config_data, indent=2, default=datetime_serializer),
            ContentType='application/json'
        )

        if cost_response:
            cost_key = f"{date_folder}cost_snapshot_{timestamp_str}.json"
            cost_data = {
                "metadata": {
                    "report_date": date_str,  # The actual date this cost data represents
                    "snapshot_timestamp": current_date.isoformat(),  # When snapshot was taken
                    "cost_period_start": cost_start_date.strftime("%Y-%m-%d"),
                    "cost_period_end": cost_start_date.strftime("%Y-%m-%d"),  # Same day
                    "region": region
                },
                "cost_data": cost_response
            }
            
            s3.put_object(
                Bucket=bucket_name,
                Key=cost_key,
                Body=json.dumps(cost_data, indent=2, default=datetime_serializer),
                ContentType='application/json'
            )

    except Exception as e:
        logger.error(f"Error saving reports: {str(e)}")
        return {
            "statusCode": 500,
            "body": {"error": f"Failed to save reports: {str(e)}"}
        }

    return {
        "statusCode": 200,
        "body": {
            "message": f"Merged inventory and cost reports saved successfully in: {date_folder}",
            "snapshot_info": {
                "date": date_str,
                "timestamp": timestamp_str,
                "folder": date_folder,
                "merged_report": merged_key,
                "config_file": config_key,
                "cost_file": cost_key if cost_response else None
            },
            "summary": {
                "total_resources": len(all_resources),
                "services_with_resources": len(merged_inventory),
                "successful_resource_types": len(successful_types),
                "failed_resource_types": len(failed_types),
                "region": region,
                "cost_period": f"{cost_start_date} (same day alignment)",
                "total_daily_cost": f"${total_cost_summary['total_unblended_cost']} {total_cost_summary['currency']}"
            }
        }
    }