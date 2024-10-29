# AWS Organization Auto-Shutdown Resources

This folder contains two Python scripts that work together to manage automatic shutdown and startup of AWS resources across multiple accounts in an AWS Organization.

## Scripts

### 1. autoshutdown-transform-event.py

This script is responsible for transforming CloudTrail events related to resource tagging and creating or updating EventBridge rules based on the tags.

Key features:
- Handles CloudTrail events for adding, updating, and removing tags on AWS resources
- Supports RDS, EC2, and Auto Scaling resources
- Converts tag values to cron expressions for scheduling
- Creates EventBridge rules based on the parsed tags and cron expressions

### 2. autoshutdown-resources.py

This script handles the actual starting and stopping of AWS resources based on the EventBridge rules created by the first script.

Key features:
- Supports starting and stopping RDS clusters
- Uses cross-account IAM roles to manage resources in different AWS accounts
- Handles errors and edge cases, such as deleting rules for non-existent resources

## Usage

These scripts are designed to work with AWS Lambda and EventBridge. They should be deployed as Lambda functions and triggered by EventBridge rules based on resource tagging events and scheduled times.

To use this system:
1. Tag your AWS resources with appropriate shutdown/startup schedules
2. The `autoshutdown-transform-event.py` script will create corresponding EventBridge rules
3. At the scheduled times, the `autoshutdown-resources.py` script will be triggered to start or stop the resources

## Configuration

The scripts use environment variables and IAM roles for configuration:

- `KEYS_TO_KEEP`: A comma-separated list of tag keys to monitor (default: "weekendautoshutdown,dailyautoshutdown")
- Cross-account access is managed using an IAM role named "CICD" in each account

## Note

This system provides a flexible way to manage resource scheduling across an AWS Organization, potentially reducing costs by automatically shutting down resources when they're not needed.