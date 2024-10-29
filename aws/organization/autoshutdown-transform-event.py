import json
import boto3
import re
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

rds_client = boto3.client('rds')
events_client = boto3.client('events')
lambda_client = boto3.client('lambda')
sts_client = boto3.client('sts')

day_map = {
    'SU': 1,
    'MO': 2,
    'TU': 3,
    'WE': 4,
    'TH': 5,
    'FR': 6,
    'SA': 7
}

keys_to_keep = os.getenv('KEYS_TO_KEEP', 'weekendautoshutdown,dailyautoshutdown').split(',')


def check_asg_tags(asg_name,account_id,region):
    ''' 
    This function checks for asg tags and verifies if keys_to_keep matches.
    If tag is missing it returns the missing tag values. 
    
    '''
    role_arn=f'arn:aws:iam::{account_id}:role/{os.getenv('assume_role_name')}'
    client = assume_role_and_get_client('autoscaling', role_arn, region, session_name='asg')
    asg_tags = client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])['AutoScalingGroups'][0].get('Tags', [])
    asg_tag_keys = {tag['Key'].lower() for tag in asg_tags}
    
    missing_keys = [key for key in keys_to_keep if key.lower() not in asg_tag_keys]
    result = {
        'asg_name': asg_name,
        'missing_keys': missing_keys
    }
    
    return result
    
def get_asg_details(instance_id,region,account_id):
    '''
    Checks if an Ec2 instance belongs to an autoscaling group or not.
    
    '''
    # Initialize the Boto3 client for EC2 and Auto Scaling
    role_arn=f'arn:aws:iam::{account_id}:role/CICD'
    ec2_client = assume_role_and_get_client('ec2', role_arn, region,session_name='ec2')
    asg_client = assume_role_and_get_client('autoscaling', role_arn, region, session_name='asg')

    # Describe the instance to get the Auto Scaling Group Name
    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
    asg_name = None

    # Extract the Auto Scaling Group name from the instance tags
    for reservation in instance_info['Reservations']:
        for instance in reservation['Instances']:
            tags = instance.get('Tags', [])
            for tag in tags:
                if tag['Key'] == 'aws:autoscaling:groupName':
                    asg_name = tag['Value']
                    break

    if asg_name:
        # Get the Auto Scaling Group details
        asg_details = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        logger.info(f"Auto Scaling Group details for instance {instance_id}: {asg_details}, No schedule to be created for this instance. ")
        return False
    else:
        logger.info(f"No Auto Scaling Group found for instance {instance_id}, schedule to be created.")
        return True
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
        client = boto3.client(
            event_source,
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )  
        return client
    except Exception as e:
        logger.error(f"Error assuming role: {str(e)}")
        raise

def parse_tag(tag):
    """
    Parse the tag into start day, start hour, end day, and end hour.
    Expected format: WKND_STARTDAY_STARTHOUR_ENDDAY_ENDHOUR_UTC
    Example: WKND_FR20_MO07_UTC
    """
    result = tag.split("_")
    result_dict = {
    "cron_type": result[0],  
    "start_part": result[1],    
    "end_part": result[2],      
    "timezone": result[3]  
}
    start_part = result_dict['start_part']
    end_part = result_dict['end_part']  
    # Extract day and hour from both parts
    start_day = start_part[:2]  
    start_hour = start_part[2:] 
    end_day = end_part[:2]     
    end_hour = end_part[2:]     
    return_dict = {
    "cron_type": result[0],  
    "start_day": start_day,     
    "start_hour": start_hour,      
    "end_day" : end_day,
    "end_hour": end_hour
}
    return return_dict



def tag_to_cron(tag):
    """
    Change the tag to cron format
    Example: WKND_FR20_MO07_UTC to 
             DD_MO20_TH07_UTC to 
    """
    
    if validate_tag(tag):
        
        result = parse_tag(tag)
        start_day = result['start_day']
        start_hour = result['start_hour']
        end_day = result['end_day']  
        end_hour = result['end_hour'] 
        cron_type = result['cron_type']
        start_day = day_map[start_day]
        end_day = day_map[end_day]
        if cron_type == "WKND":
           stop = f"stop: 0 {start_hour} ? * {start_day} *"
           start = f"start: 0 {end_hour} ? * {end_day} *"
        elif cron_type == "DD":
           stop = f"stop: 0 {start_hour} ? * {start_day}-{end_day} *"
           start = f"start: 0 {end_hour} ? * {start_day}-{end_day + 1} *"
        logger.info(f"Stop: {stop}, Start: {start}")
       
        return stop, start
    else:
      logger.error("Invalid tag format.")
      raise Exception("Invalid tag format")

def validate_tag(tag):
    '''
    Validate tag syntax
    '''
    # Define the regular expression for the expected tag format
    pattern = r"^(WKND|DD)_([A-Z]{2})(\d{2})_([A-Z]{2})(\d{2})_UTC$"
    
    # List of valid days
    valid_days = {"MO", "TU", "WE", "TH", "FR", "SA", "SU"}
    
    # Match the pattern and extract components
    match = re.match(pattern, tag)
    if match:
        _, day1, hour1, day2, hour2 = match.groups()
        
        # Convert hours to integers
        hour1 = int(hour1)
        hour2 = int(hour2)
        
        # Check if the days are valid and hours are in the range 00-23
        if day1 in valid_days and day2 in valid_days and 0 <= hour1 <= 23 and 0 <= hour2 <= 23:
            return True
        else:
            return False
    else:
        return False
    
def transform_cloudtrail_event(json_data):
    '''
    Transform the cloudtrail event for ec2 or asg or rds event source to fetch tag details. 
    '''
    event_source = json_data['eventSource'].split('.')[0]
    event_name = json_data['eventName']
    region = json_data['awsRegion']
    accountid = json_data['recipientAccountId']
    
    if event_source == 'rds':
        resource_name = json_data['requestParameters']['resourceName']
        tags_key = 'tags' if 'tags' in json_data['requestParameters'] else 'tagKeys'
        if tags_key == 'tagKeys':
            filtered_data = [json_data['requestParameters'][tags_key]][0]
        elif tags_key == 'tags':
            tags_dict = {tag['key']: tag['value'] for tag in json_data['requestParameters'][tags_key]}
            filtered_data = {key: value for key, value in tags_dict.items() if key in keys_to_keep}
        else:
            raise Exception("Invalid tag format in eventsource")
        result = {
            'resource_name': resource_name,
            'region': region,
            'accountId': accountid,
            'dbname': resource_name.split(":")[-1],
            'service': event_source,
            'event_name': event_name,
            'tags': filtered_data,
            'event_source': event_source, 
        }
       
        return result
        
    elif event_source == 'ec2':
        resource_name = json_data['requestParameters']["resourcesSet"]["items"][0]["resourceId"]
        filtered_data = {item["key"]: item["value"] for item in json_data["requestParameters"]["tagSet"]["items"] if item["key"] in keys_to_keep}
        
        result = {
            'resource_name': resource_name,
            'region': region,
            'accountId': accountid,
            'service': event_source,
            'event_name': event_name,
            'tags': filtered_data,
            'event_source': event_source, 
        }
        rule_create=get_asg_details(result['resource_name'],result['region'],result['accountId']) 
        if rule_create:
            logger.info(f"Transformed CloudTrail event: {result}")
            return result
        else:
            raise EC2ASGError(f"{result['resource_name']} belongs to autoscaling group")
    elif event_source == 'autoscaling':
        resource_name =  next((tag["resourceId"] for tag in json_data["requestParameters"]["tags"] if "resourceId" in tag), None)
        filtered_data = {item["key"]: item["value"] for item in json_data["requestParameters"]["tags"] if item["key"] in keys_to_keep}
        result = {
            'resource_name': resource_name,
            'region': region,
            'accountId': accountid,
            'service': event_source,
            'event_name': event_name,
            'tags': filtered_data,
            'event_source': event_source,
        }
        logger.info(f"Transformed CloudTrail event: {result}")
        return result
def create_event_rule(cron_expression,result):
    """
    Creates a CloudWatch Event Rule and sets the Lambda function as the target.
    ('Stop: 0 08 ? * 3 *', 'Start: 0 20 ? * 6 *')
    """
    
    lambda_function_arn = os.getenv('SHUTDOWN_LAMBDA_FUNCTION_ARN')
    #lambda_function_arn = 'arn:aws:lambda:eu-central-1:188542856001:function:autoshutdown-resources'
    try:
        for cron in cron_expression:
            print(cron)
            action = cron.split(":")[0]
            schedule = cron.split(":")[1].strip()
            name = result['resource_name'].split(":")[-1] if ":" in result['resource_name'] else result['resource_name']
            ##TODO have shorter names
            rule_name = f"{result['cron_type'][0]}_{result['accountId']}_{name[-20:]}_{action}_{result['event_source']}".lower()
            print(rule_name)
            # if len(rule_name) > 64:
            #   raise Exception ('Rule name too long')
            
            event_rule=events_client.put_rule(
                Name=rule_name,
                ScheduleExpression=f"cron({schedule})",
                State='ENABLED',
                Tags=[
                     {
                        'Key': 'accountId',
                        'Value': result['accountId'],
                      },
                      {
                        'Key': 'action',
                        'Value': action,
                      },
                      {
                        'Key': 'project',
                        'Value': 'devops-autoshutdown',
                      },
                      {
                        'Key': 'resourceId',
                        'Value': result['resource_name'],
                      },
                ],
                Description=f"Trigger Lambda function for {rule_name} in UTC time zone",
            
            )
            result['rule_arn']=event_rule['RuleArn']
            events_client.put_targets(
                Rule=rule_name,
                Targets=[
                    {
                        'Id': f"target-autoshutdown",
                        'Arn': lambda_function_arn,
                        'Input': json.dumps({**result, 'action': action})
                    }
                ]
            )
            logger.info(f"Created CloudWatch Event Rule '{rule_name}' with cron expression '{cron}' for event {result}")
    except Exception as e:
        logger.error(f"Error creating CloudWatch Event Rule: {str(e)}")
def delete_rule_targets(rule_name):
    try:
        targets_response = events_client.list_targets_by_rule(Rule=rule_name)
        if targets_response['Targets']:
            target_ids = [target['Id'] for target in targets_response['Targets']]
            remove_response = events_client.remove_targets(
                Rule=rule_name,
                Ids=target_ids
            )
            logger.info(f"Removed targets {remove_response} for rule: {rule_name}")
        else:
            logger.info(f"No targets found for the rule: {rule_name}")
    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")        
    
def delete_rule_by_name(search_string):
    try:
        rules = events_client.list_rules(NamePrefix=search_string)
        logger.info(f"Rules to be deleted: {rules}")
        for rule in rules['Rules']:
            delete_rule_targets(rule['Name'])
            events_client.delete_rule(Name=rule['Name'])
    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")
        
 

def lambda_handler(event, context):
    json_data = event['detail']
    result=transform_cloudtrail_event(json_data)
    logger.info(f"Transformed CloudTrail event: {result}")
    
    try:
        if result['event_name'] in ['AddTagsToResource','CreateTags','CreateOrUpdateTags'] :
            for tag_key,tag_value in result['tags'].items():
                result['cron_type']=tag_value.split('_')[0]
                cron_expression= tag_to_cron(tag_value)
                create_event_rule(cron_expression, result)    
        elif result['event_name'] in ['RemoveTagsFromResource','DeleteTags']: 
            for key in result['tags']:
                if key in keys_to_keep:
                    if result['event_source'] == 'rds':
                        search_string = f"{key[0]}_{result['accountId']}_{result['dbname'][-20:]}".lower()
                    elif result['event_source'] == 'ec2':
                        search_string = f"{key[0]}_{result['accountId']}_{result['resource_name'][-20:]}".lower()  
                    #TODO Need to improve     
                    elif result['event_source'] == 'autoscaling':
                            #ASG doesn't send exact tag deleted in its cloudtrail event. 
                            tag_removed = check_asg_tags(result['resource_name'],result['accountId'],result['region'])
                            print(tag_removed)
                            for tag in tag_removed['missing_keys']:
                                if tag:
                                   search_string = f"{tag[0]}_{result['accountId']}_{result['resource_name'][-20:]}".lower()
                                   delete_rule_by_name(search_string)
                                else:
                                    logger.info(f"No rule to be deleted for asg {result['resource_name']}")
                                    search_string = 'None'
                delete_rule_by_name(search_string)
    except Exception as e:
        logger.error(f"Error occurred: {str(e)}" + f"event: {result}")
