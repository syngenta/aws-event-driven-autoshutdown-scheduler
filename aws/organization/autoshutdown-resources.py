import boto3
import logging
import json
from botocore.exceptions import ClientError
import os
logger = logging.getLogger()
logger.setLevel(logging.INFO)

sts_client = boto3.client('sts')
events_client=boto3.client('events')
role_name = os.getenv('ROLE_NAME')
# Function to assume role and create RDS client for the target account
def assume_role_and_get_client(event_source,role_arn,region, session_name='AssumeRoleSession1'):
    try:
        # Assume the role
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )  
        # Get temporary credentials
        credentials = assumed_role['Credentials']
        # Create RDS client using assumed role credentials
        rds_client = boto3.client(
            event_source,
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )  
        return rds_client
    except Exception as e:
        logger.error(f"Error assuming role: {str(e)}")
        raise

def delete_rule_targets(rule_name):
    try:
       targets_response = events_client.list_targets_by_rule(Rule=rule_name)
       if targets_response['Targets']:
          target_ids = [target['Id'] for target in targets_response['Targets']]
          remove_response = events_client.remove_targets(
              Rule=rule_name,
              Ids=target_ids
          )
          logger.info(f"Removed Targets Response: { remove_response }")
       else:
          print("No targets found for the rule:", rule_name)
          logger.info(f"No targets found for the rule: {rule_name}")
    except events_client.exceptions.ResourceNotFoundException as e:
        logger.error(f"Error: {e}. The EventBridge rule '{rule_name}' was not found.")
        raise e
    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")  
        raise e
        
def delete_rule_by_name(rule_name):
    try:
            delete_rule_targets(rule_name)
            events_client.delete_rule(Name=rule_name)
    except events_client.exceptions.ResourceNotFoundException as e:
        logger.info(f"Error: {e}. The EventBridge rule '{rule_name}' was not found.")
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        logger.error(f"Error occurred: {str(e)}")
        raise 


def get_asg_details(rule_name,asg_name,account_id,region):
    role_arn=f'arn:aws:iam::{account_id}:role/{role_name}'
    # ec2_client =  assume_role_and_get_client('ec2', role_arn, region,session_name='ec2')
    asg_client =  assume_role_and_get_client('autoscaling', role_arn, region, session_name='asg')

    if asg_name:
        asg_details = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        if asg_details['AutoScalingGroups']:
            asg = asg_details['AutoScalingGroups'][0]
            result = {
                'AutoScalingGroupName': asg['AutoScalingGroupName'],
                'DesiredCapacity': asg['DesiredCapacity'],
                'MinSize': asg['MinSize'],
                'MaxSize': asg['MaxSize'],
               
            }
            return result
        else:
            logger.info(f"ASG Details not found,deleting rule {rule_name}")
            delete_rule_by_name(rule_name)
            return False
        
    else:
        logger.info(f"No Auto Scaling Group found for {rule_name}")
        
        return False
def update_event_rule(rule_arn, target_id, new_input):
        """Update the input of a single target for an AWS EventBridge rule by merging current and new input."""
        client = boto3.client('events')
        try:
            rule_name = rule_arn.split('/')[-1]
            existing_targets = client.list_targets_by_rule(Rule=rule_name)['Targets']
            target = next((t for t in existing_targets if t['Id'] == target_id), None)
            if not target:
                print(f"Target '{target_id}' not found in rule '{rule_name}'.")
                return
            current_input = json.loads(target.get('Input', '{}'))
            merged_input = current_input | new_input
          
            target['Input'] = str(json.dumps(merged_input))
            client.put_targets(Rule=rule_name, Targets=[target])
            logger.info(f"Successfully updated target '{target_id}' for rule '{rule_name}'.")
        except Exception as e:
            logger.error(f"Error updating target '{target_id}' for rule '{rule_name}': {str(e)}")
            raise
    

def lambda_handler(event, context):
    rule_name=event.get('rule_arn').split("rule/")[1]
    action = event.get('action')  # 'start' or 'stop'
    accountId=event.get('accountId')
    instance_id = event.get('resource_name')  # DBClusterIdentifier
    role_arn = f'arn:aws:iam::{accountId}:role/CICD'  # Cross-account role ARN
    region = event.get('region')
    print(f"Started {action} action for {event.get('event_source') }:{instance_id} belonging to {accountId}")
    if event.get('event_source') == 'rds':
        
        if not instance_id:
            raise ValueError("instanceId is required")
        
        if action not in ['start', 'stop']:
            raise ValueError("Action must be 'start' or 'stop'")

        # Assume the role and get the RDS client for the target account
        rds_client = assume_role_and_get_client(event.get('event_source'),role_arn,region)

        # Get details of the provided DBClusterIdentifier
        try:
            cluster = rds_client.describe_db_clusters(DBClusterIdentifier=instance_id)['DBClusters'][0]
            if action == 'stop':
                if cluster['Status'] == 'available':
                    logger.info(f"Stopping cluster: {instance_id}")
                    rds_client.stop_db_cluster(DBClusterIdentifier=instance_id)
                else:
                    logger.info(f"Cluster {instance_id} is not available to stop." )
            elif action == 'start':
                if cluster['Status'] == 'stopped':
                    logger.info(f"Starting cluster: {instance_id}")
                    rds_client.start_db_cluster(DBClusterIdentifier=instance_id)

        except rds_client.exceptions.DBClusterNotFoundFault as error:
                logger.error((f"{error}:Cluster {instance_id} not found, deleting the rule {rule_name}"))
                delete_rule_by_name(rule_name)
        except Exception as e:
            logger.error(f"Error occurred: {str(e)}")
           
        
    elif event.get('event_source') == 'ec2':
        if not instance_id:
            raise ValueError("instanceId is required")

        if action not in ['start', 'stop']:
            raise ValueError("Action must be 'start' or 'stop'")

        # Assume the role and get the EC2 client for the target account
        ec2_client = assume_role_and_get_client(event.get('event_source'),role_arn, region)

        # Get details of the provided InstanceId
        try:
            instance = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
            if action == 'stop':
                if instance['State']['Name'] == 'running':
                    logger.info(f"Stopping instance: {instance_id}")
                    ec2_client.stop_instances(InstanceIds=[instance_id])
                else:
                    logger.info(f"Instance {instance_id} is not in a running state.")
            elif action == 'start':
                if instance['State']['Name'] == 'stopped':
                    logger.info(f"Starting instance: {instance_id}")
                    ec2_client.start_instances(InstanceIds=[instance_id])
                else:
                    logger.info(f"Instance {instance_id} is not in a stopped state.")
        except IndexError:
            logger.error((f"Cluster {instance_id} not found, deleting the rule if present"))
            delete_rule_by_name(rule_name)
        except ClientError as e:
            if 'InvalidInstanceID.NotFound' in str(e):
                logger.error((f"{error}:Cluster {instance_id} not found, deleting the rule if present"))
                delete_rule_by_name(rule_name)
            else:
            # Handle other potential errors
                raise e
        except Exception as e:
            logger.error(f"Error occurred: {str(e)}")
            
    elif event.get('event_source') == 'autoscaling':
        if not instance_id:
            raise ValueError("instanceId is required")

        if action not in ['start', 'stop']:
            raise ValueError("Action must be 'start' or 'stop'")
            
        autoscaling_client= assume_role_and_get_client('autoscaling', role_arn, region, session_name='asg')
        data = get_asg_details(rule_name,event.get('resource_name'),event.get('accountId'),event.get('region'))
        try:
            autoscaling_group = autoscaling_client.describe_auto_scaling_groups(AutoScalingGroupNames=[instance_id])['AutoScalingGroups'][0]
            if action == 'stop':
                rule_update=str(event.get('rule_arn')).replace('stop','start')
                update_event_rule(rule_update,'target-autoshutdown',data)
                if autoscaling_group['DesiredCapacity'] > 0:
                    logger.info(f"Scaling {instance_id} to 0")
                    autoscaling_client.update_auto_scaling_group(AutoScalingGroupName=instance_id, DesiredCapacity=0,MinSize=0,MaxSize=0)
                else:
                    logger.info(f"{instance_id} is already scaled to 0.")
            elif action == 'start':
                print(autoscaling_group)
                print(event)
                if autoscaling_group['DesiredCapacity'] == 0:
                    logger.info(f"Scaling {instance_id} ")
                    autoscaling_client.update_auto_scaling_group(AutoScalingGroupName=instance_id, DesiredCapacity=event['DesiredCapacity'],MinSize=event['MinSize'],MaxSize=event['MaxSize'])
                else:
                    logger.info(f"{instance_id} is already scaled desired size.")
        except Exception as e:
            logger.error(f"Error occurred: {str(e)}")