## Deployment Steps:

    Deploy the cf-event-rule.yaml file as a CloudFormation StackSet or deploy individually to preferred accounts:
        Use AWS CloudFormation to create a StackSet from the provided YAML file.
        Configure the StackSet to deploy across targeted AWS accounts and regions.
        Ensure IAM roles and permissions are correctly configured for StackSet deployment across multiple accounts.
        Monitor StackSet operations to verify successful creation of resources in each account.

    Deploy Lambda Functions in the Centralized Account:
        Package the Lambda function code and upload it to an S3 bucket accessible by the centralized account.
        Ensure Lambda functions have appropriate IAM roles, permissions, and environment variables set up for inter-account operations.
        
    Create an EventBridge EventBus in the Centralized Account:
        In the centralized account, navigate to Amazon EventBridge and create a custom EventBus. This event bus needs to be provided as an input to CF stack. Make sure correct permissions are assigned to eventbus to receive events form other accounts. 
        