# AWS Resource Auto-Shutdown Scheduler

## Overview
This open-source project provides an automated shutdown and startup solution for AWS EC2,AutoScaling groups and RDS resources. It's designed to help organizations reduce costs and minimize their carbon footprint by automatically managing resource usage during off-hours and weekends.

## Features
- Event-driven architecture for real-time schedule updates based on resource tags. 
- Centralized approach for larger org and business units while keeping implementation cost low. 
- Support for EC2, RDS, DocumentDB, and AutoScaling Groups
- Customizable shutdown schedules using resource tags
- Easy integration with existing AWS environments
- An alternative to [instance-scheduler-on-aws](https://aws.amazon.com/solutions/implementations/instance-scheduler-on-aws/)

## Why Use This?
- **Cost Optimization**: Automatically shut down idle resources to reduce AWS bills
- **Environmental Impact**: Minimize carbon footprint by reducing unnecessary compute usage
- **Flexibility**: Customize schedules to fit your team's working hours and needs
- **Mimimum Efforts**: Minimum effort required from teams/users as it uses a centralized approach

## How It Works
The solution uses AWS resource tags to define shutdown and startup schedules. When you apply or modify these tags, the system automatically updates the corresponding schedules in real-time.

### Supported Tags
1. **Weekend Auto-shutdown**: `weekendautoshutdown`
   Format: `WKND_<StartDay><StartTime>_<EndDay><EndTime>_UTC`
   Example: `WKND_FR20_MO07_UTC` (Shutdown Friday 8PM, restart Monday 7AM UTC)

2. **Daily Auto-shutdown**: `dailyautoshutdown`
   Format: `DD_<StartDay><StartTime>_<EndDay><EndTime>_UTC`
   Example: `DD_MO20_TH07_UTC` (Shutdown Monday 8PM, restart Thursday 7AM UTC)

## Getting Started
1. Clone this repository
2. Set up the necessary AWS permissions (detailed in `SETUP.md`)
3. Deploy the solution to your AWS account (instructions in `DEPLOYMENT.md`)
4. Start tagging your resources!

## Important Considerations
- Exercise caution when using in production environments
- May not be suitable for EKS clusters with Karpenter or Cluster Autoscaler
- For RDS, be aware of potential conflicts with maintenance windows

## Contributing
We welcome contributions! Please see our `CONTRIBUTING.md` file for details on how to get involved.

## License
This project is licensed under the MIT License - see the `LICENSE` file for details.



## Support
If you encounter any issues or have questions, please file an issue on the GitHub repository.

Remember: Always follow AWS best practices for security and resource management when using this tool.
