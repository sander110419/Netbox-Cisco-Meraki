# Cisco Meraki to NetBox Synchronization Tool

This script synchronizes Cisco Meraki access points to NetBox, providing an automated way to maintain your NetBox DCIM database with accurate information from your Meraki environment.

## Overview

The Meraki_to_Netbox.py script discovers and synchronizes the following Meraki resources to NetBox:
- Meraki Networks → NetBox Sites
- Meraki Access Points → NetBox Devices
- AP IP Addresses → NetBox IP Addresses
- AP MAC Addresses → NetBox Interface MAC Addresses

## Prerequisites

- Python 3.6+
- Access to a Cisco Meraki dashboard with API access
- A running NetBox instance with API access
- Required Python packages (see Installation)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/Meraki_to_Netbox.git
```

2. Install the required dependencies:
```bash
pip install requests pynetbox tqdm urllib3
```

## Configuration

The script can be configured using command-line arguments or environment variables:

### Environment Variables
- `MERAKI_API_KEY`: Your Cisco Meraki API key
- `NETBOX_URL`: URL of your NetBox instance
- `NETBOX_TOKEN`: NetBox API token with write access

## Usage

### Basic Usage
```bash
python Meraki_to_Netbox.py --meraki-api-key your-api-key --netbox-url https://your-netbox-instance/ --netbox-token your-netbox-token
```

### Using Environment Variables
```bash
export MERAKI_API_KEY=your-api-key
export NETBOX_URL=https://your-netbox-instance/
export NETBOX_TOKEN=your-netbox-token
python Meraki_to_Netbox.py
```

## Features

- **Automatic Discovery**: Automatically discovers all Meraki networks and access points
- **Resource Mapping**: Maps Meraki resources to appropriate NetBox objects
- **Idempotent Operation**: Can be run multiple times safely, updating existing resources
- **Tagging**: Adds "meraki-sync" tag to all created/updated objects in NetBox
- **Site Detection**: Intelligently extracts facility IDs from network names for site mapping
- **Name Handling**: Automatically handles truncation and uniqueness requirements for device names
- **Interface Creation**: Creates LAN interfaces for access points with MAC addresses

## Data Synchronization Details

1. **Networks**: Meraki networks are mapped to NetBox sites, with facility IDs extracted from network names
2. **Access Points**: Discovered through client information with descriptions starting with "AP" or "APN"
3. **Device Types**: Created based on detected Meraki AP models
4. **Interfaces**: LAN interfaces created for each AP with their MAC addresses
5. **IP Addresses**: Associated with the LAN interface of each AP and set as primary IP

## Troubleshooting

- **SSL Certificate Issues**: The script disables SSL verification by default. For production, consider properly configuring SSL certificates.
- **Rate Limiting**: For large deployments, the script uses progress tracking via tqdm.
- **Logging**: The script logs operations at INFO level. Review logs for troubleshooting.
- **Device Name Conflicts**: If device names conflict within a site, the script automatically appends a numerical suffix.

## Notes

- The script is designed to be run periodically to keep NetBox updated with the current state of Meraki access points.
- All objects created or updated by the script receive a "meraki-sync" tag for identification.
- The script uses facility IDs in network names (e.g., "24-Dinant" has facility ID "24") to match or create sites in NetBox.
- Meraki AP client information is used to discover access points, looking for descriptions starting with "AP" or "APN".
- The script handles name truncation to comply with NetBox's 64-character name limit.
