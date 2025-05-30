#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import requests
import re
from pynetbox import api
from pynetbox.core.query import RequestError
from tqdm import tqdm
import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def sanitize_slug(text):
    """
    Sanitize a string to create a valid Netbox slug
    - Convert to lowercase
    - Replace spaces with hyphens
    - Remove any characters that aren't letters, numbers, underscores, or hyphens
    """
    # Convert to lowercase and replace spaces with hyphens
    slug = text.lower().replace(" ", "-")
    # Remove any characters that aren't allowed
    slug = re.sub(r'[^a-z0-9_-]', '', slug)
    # Ensure slug isn't empty and doesn't start/end with hyphens
    slug = slug.strip('-')
    if not slug:
        slug = "meraki"  # Default if nothing valid remains
    return slug

def truncate_name(name, max_length=64):
    """
    Truncate a name by:
    1. Removing everything after and including the first decimal point
    2. Ensuring the result doesn't exceed max_length characters
    """
    # First, remove everything after and including the first decimal point
    if '.' in name:
        name = name.split('.')[0]
        logger.debug(f"Removed decimal portion, new name: {name}")
    
    # Then ensure it doesn't exceed max_length
    if len(name) > max_length:
        logger.warning(f"Name '{name}' exceeds {max_length} characters, truncating")
        name = name[:max_length]
    
    return name

def truncate_description(description, max_length=200):
    """
    Truncate a description to ensure it doesn't exceed max_length characters
    """
    if len(description) > max_length:
        logger.warning(f"Description exceeds {max_length} characters, truncating")
        return description[:max_length-3] + "..."
    return description

def get_meraki_networks(api_key):
    """Get all networks from Meraki"""
    logger.info("Getting networks from Meraki")
    
    url = "https://api.meraki.com/api/v1/organizations"
    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    # Get all organizations
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        logger.error(f"Error fetching organizations: {response.status_code} - {response.text}")
        raise Exception(f"Failed to get organizations from Meraki: {response.status_code}")
    
    organizations = response.json()
    logger.info(f"Found {len(organizations)} organizations")
    
    all_networks = []
    
    # Get networks for each organization
    for org in organizations:
        org_id = org['id']
        org_name = org['name']
        logger.info(f"Getting networks for organization: {org_name}")
        
        url = f"https://api.meraki.com/api/v1/organizations/{org_id}/networks"
        response = requests.get(url, headers=headers, verify=False)
        
        if response.status_code != 200:
            logger.error(f"Error fetching networks for org {org_name}: {response.status_code} - {response.text}")
            continue
        
        networks = response.json()
        logger.info(f"Found {len(networks)} networks in organization {org_name}")
        
        for network in networks:
            network['org_name'] = org_name
            network['org_id'] = org_id
        
        all_networks.extend(networks)
    
    return all_networks

def extract_facility_id(network_name):
    """Extract facility ID from network name (e.g., '24-Dinant' -> 24)"""
    # Try to match patterns like "24-Dinant" or "02-Gent"
    match = re.match(r'^(\d+)-', network_name)
    if match:
        facility_id = match.group(1)
        # Remove leading zeros
        facility_id = str(int(facility_id))
        return facility_id
    
    return None

def get_ap_clients_in_network(api_key, network_id):
    """Get all access point clients in a Meraki network"""
    # Use the clients endpoint instead of devices
    url = f"https://api.meraki.com/api/v1/networks/{network_id}/clients"
    
    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    # Add query parameters - we want all clients, not just recently active ones
    params = {
        "timespan": 2592000,  # Look back 30 days (in seconds)
        "perPage": 1000       # Maximum page size
    }
    
    all_clients = []
    
    # We may need to handle pagination
    while url:
        response = requests.get(url, headers=headers, params=params, verify=False)
        if response.status_code != 200:
            logger.error(f"Error fetching clients for network {network_id}: {response.status_code} - {response.text}")
            return []
        
        clients = response.json()
        logger.info(f"Found {len(clients)} clients in network {network_id}")
        
        # Add clients to our list
        all_clients.extend(clients)
        
        # Check for pagination
        if 'Link' in response.headers and 'next' in response.headers['Link']:
            url = response.headers['Link'].split('next')[1].split(';')[0].strip('<>')
            params = {}  # Don't need params for the next URL as they're included
        else:
            url = None
    
    # Filter clients for APs - those with description starting with "AP" or "APN"
    ap_clients = [client for client in all_clients 
                  if client.get('description') and 
                  (client['description'].startswith('AP') or 
                   client['description'].startswith('APN'))]
    
    logger.info(f"Found {len(ap_clients)} access points in network {network_id}")
    return ap_clients

def get_device_details(api_key, serial):
    """Get detailed information about a device"""
    url = f"https://api.meraki.com/api/v1/devices/{serial}"
    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        logger.error(f"Error fetching details for device {serial}: {response.status_code} - {response.text}")
        return {}
    
    return response.json()

def get_or_create_tag(nb, tag_name, tag_slug, tag_description):
    """Get or create a tag in Netbox"""
    # Try to find the tag first
    try:
        tag = nb.extras.tags.get(slug=tag_slug)
        if tag:
            logger.info(f"Found existing tag: {tag_slug}")
            return tag
    except Exception as e:
        logger.debug(f"Error getting tag {tag_slug}: {str(e)}")
    
    # Create the tag if it doesn't exist
    logger.info(f"Creating new tag: {tag_slug}")
    return nb.extras.tags.create(
        name=tag_name,
        slug=tag_slug,
        description=tag_description
    )

def get_or_create_device_type(nb, model, manufacturer_name, tags):
    """Get or create a device type in Netbox"""
    try:
        device_type = nb.dcim.device_types.get(model=model)
        if device_type:
            return device_type
    except Exception as e:
        logger.debug(f"Error getting device type {model}: {str(e)}")
    
    # Get or create manufacturer
    try:
        manufacturer = nb.dcim.manufacturers.get(name=manufacturer_name)
        if not manufacturer:
            manufacturer = nb.dcim.manufacturers.create(
                name=manufacturer_name,
                slug=sanitize_slug(manufacturer_name),
                description=f'Created by Meraki sync script'
            )
        manufacturer_id = manufacturer.id
    except Exception as e:
        logger.debug(f"Error getting manufacturer {manufacturer_name}: {str(e)}")
        manufacturer = nb.dcim.manufacturers.create(
            name=manufacturer_name,
            slug=sanitize_slug(manufacturer_name),
            description=f'Created by Meraki sync script'
        )
        manufacturer_id = manufacturer.id
    
    # Create device type with a slug based on the model name
    model_slug = sanitize_slug(model)
    return nb.dcim.device_types.create(
        model=model,
        manufacturer=manufacturer_id,
        slug=model_slug,
        tags=tags
    )

def get_or_create_device_role(nb, name, tags):
    """Get or create a device role in Netbox"""
    try:
        role = nb.dcim.device_roles.get(name=name)
        if role:
            return role
    except Exception as e:
        logger.debug(f"Error getting device role {name}: {str(e)}")
    
    return nb.dcim.device_roles.create(
        name=name,
        slug=sanitize_slug(name),
        vm_role=False,
        tags=tags
    )

def get_or_create_site(nb, name, facility_id, description, tags):
    """Get or create a site in Netbox with facility_id"""
    # First try to find site by facility ID directly
    try:
        sites = nb.dcim.sites.filter(facility=facility_id)
        if sites and len(sites) > 0:
            logger.info(f"Found existing site by facility ID {facility_id}: {sites[0].name}")
            return sites[0]
    except Exception as e:
        logger.debug(f"Error searching for site with facility ID {facility_id}: {str(e)}")
    
    # If not found by facility ID, continue with the existing logic
    try:
        # Try by exact name
        site = nb.dcim.sites.get(name=name)
        if site:
            logger.info(f"Found existing site by name: {name}")
            # Update facility_id if needed
            if site.facility != facility_id:
                site.facility = facility_id
                site.save()
                logger.info(f"Updated facility_id for site {name} to {facility_id}")
            return site
        
        # Try by slug as a fallback
        slug = sanitize_slug(name)
        site = nb.dcim.sites.get(slug=slug)
        if site:
            logger.info(f"Found existing site by slug: {slug}")
            # Update facility_id if needed
            if site.facility != facility_id:
                site.facility = facility_id
                site.save()
                logger.info(f"Updated facility_id for site {site.name} to {facility_id}")
            return site
        
        # Try with case-insensitive name search (using API filtering)
        sites = nb.dcim.sites.filter(name__ic=name)
        if sites and len(sites) > 0:
            logger.info(f"Found existing site by case-insensitive name: {sites[0].name}")
            # Update facility_id if needed
            if sites[0].facility != facility_id:
                sites[0].facility = facility_id
                sites[0].save()
                logger.info(f"Updated facility_id for site {sites[0].name} to {facility_id}")
            return sites[0]
    except Exception as e:
        logger.debug(f"Error getting site {name}: {str(e)}")
    
    # If site wasn't found, check if a site with similar name exists (more aggressive search)
    # This helps catch variations like "57-Genk" vs "57 - Genk" or "57 Genk"
    try:
        # Remove special characters and spaces for comparison
        simplified_name = re.sub(r'[^a-zA-Z0-9]', '', name).lower()
        all_sites = nb.dcim.sites.all()
        
        for site in all_sites:
            # Compare simplified names
            simplified_site_name = re.sub(r'[^a-zA-Z0-9]', '', site.name).lower()
            if simplified_site_name == simplified_name:
                logger.info(f"Found existing site with similar name: {site.name}")
                # Update facility_id if needed
                if site.facility != facility_id:
                    site.facility = facility_id
                    site.save()
                    logger.info(f"Updated facility_id for site {site.name} to {facility_id}")
                return site
    except Exception as e:
        logger.debug(f"Error searching for site with similar name {name}: {str(e)}")
    
    # Attempt to create new site, but handle potential conflicts gracefully
    logger.info(f"Creating new site: {name} with facility_id {facility_id}")
    try:
        return nb.dcim.sites.create(
            name=name,
            status='active',
            slug=sanitize_slug(name),
            facility=facility_id,
            description=description,
            tags=tags
        )
    except RequestError as e:
        # If site already exists (common error), try to find and return it
        if "site with this name already exists" in str(e) or "site with this slug already exists" in str(e):
            logger.warning(f"Site creation failed because site already exists. Trying to retrieve existing site.")
            
            # First try by exact name again (it might have been created in between our check and create)
            try:
                site = nb.dcim.sites.get(name=name)
                if site:
                    logger.info(f"Retrieved existing site by name: {name}")
                    return site
            except Exception as inner_e:
                logger.debug(f"Error retrieving site by name after creation failure: {str(inner_e)}")
            
            # Try by slug as a fallback
            try:
                slug = sanitize_slug(name)
                site = nb.dcim.sites.get(slug=slug)
                if site:
                    logger.info(f"Retrieved existing site by slug: {slug}")
                    return site
            except Exception as inner_e:
                logger.debug(f"Error retrieving site by slug after creation failure: {str(inner_e)}")
                
            # If we still can't find it, raise the original error
            raise
        else:
            # If it's a different error, re-raise it
            raise


def get_or_create_ip_address(nb, ip_address, description, tags, interface_id=None):
    """Get or create an IP address in Netbox"""
    # Ensure it has CIDR notation
    if '/' not in ip_address:
        cidr = f"{ip_address}/32"
    else:
        cidr = ip_address
    
    # Extract just the IP part without the subnet mask
    ip_only = cidr.split('/')[0]
    
    try:
        # First try exact match with the CIDR
        ip = nb.ipam.ip_addresses.get(address=cidr)
        if ip:
            logger.info(f"Found existing IP address: {cidr}")
            
            # Update interface assignment if needed
            if interface_id and (ip.assigned_object_id != interface_id or ip.assigned_object_type != 'dcim.interface'):
                ip.assigned_object_id = interface_id
                ip.assigned_object_type = 'dcim.interface'
                ip.save()
                logger.info(f"Updated interface assignment for IP: {cidr}")
                
            return ip
    except Exception as e:
        logger.debug(f"Error getting IP address {cidr}: {str(e)}")
    
    # If exact match fails, try to find IP by address only (without subnet mask)
    try:
        # Use filter to find any IP address with the same address part
        ips = list(nb.ipam.ip_addresses.filter(address__isw=ip_only))
        if ips:
            logger.info(f"Found existing IP address with different prefix: {ips[0].address}")
            ip = ips[0]
            
            # Update interface assignment if needed
            if interface_id and (ip.assigned_object_id != interface_id or ip.assigned_object_type != 'dcim.interface'):
                ip.assigned_object_id = interface_id
                ip.assigned_object_type = 'dcim.interface'
                ip.save()
                logger.info(f"Updated interface assignment for IP: {ip.address}")
                
            return ip
    except Exception as e:
        logger.debug(f"Error filtering IP address {ip_only}: {str(e)}")
    
    # Create new IP address if not found
    try:
        ip_data = {
            'address': cidr,
            'description': description,
            'status': 'active',
            'tags': tags
        }
        
        if interface_id:
            ip_data['assigned_object_type'] = 'dcim.interface'
            ip_data['assigned_object_id'] = interface_id
        
        logger.info(f"Creating new IP address: {cidr}")
        return nb.ipam.ip_addresses.create(**ip_data)
    except RequestError as e:
        # Handle duplicate IP address error
        if "Duplicate IP address found" in str(e):
            logger.warning(f"Duplicate IP found when creating {cidr}. Trying to retrieve existing IP.")
            
            # The error message contains the existing IP with correct prefix
            match = re.search(r'Duplicate IP address found in global table: ([\d\.]+/\d+)', str(e))
            if match:
                existing_cidr = match.group(1)
                try:
                    # Try to get the existing IP with the correct prefix
                    ip = nb.ipam.ip_addresses.get(address=existing_cidr)
                    if ip:
                        logger.info(f"Retrieved existing IP: {existing_cidr}")
                        
                        # Update interface assignment if needed
                        if interface_id and (ip.assigned_object_id != interface_id or ip.assigned_object_type != 'dcim.interface'):
                            ip.assigned_object_id = interface_id
                            ip.assigned_object_type = 'dcim.interface'
                            ip.save()
                            logger.info(f"Updated interface assignment for IP: {existing_cidr}")
                            
                        return ip
                except Exception as inner_e:
                    logger.debug(f"Error retrieving existing IP {existing_cidr}: {str(inner_e)}")
            
        # If we get here, re-raise the exception
        logger.error(f"Error creating IP address {cidr}: {str(e)}")
        raise

def get_or_create_device(nb, device_name, device_type_id, role_id, site_id, status, tags, serial=None, description=None):
    """Get a device by name across all sites, or create if it doesn't exist"""
    try:
        # First try to find by name anywhere in Netbox (not just in current site)
        existing_devices = nb.dcim.devices.filter(name=device_name)
        if existing_devices and len(existing_devices) > 0:
            nb_device = existing_devices[0]
            logger.info(f"Found existing device with name '{device_name}' in site '{nb_device.site.name}'")
            
            # Update device with new information if needed
            update_needed = False
            # Only update device_type if current type is the generic "Meraki AP"
            if nb_device.device_type.id != device_type_id and nb_device.device_type.model == "Meraki AP":
                nb_device.device_type = device_type_id
                update_needed = True
            if nb_device.role.id != role_id:
                nb_device.role = role_id
                update_needed = True
            if serial and nb_device.serial != serial:
                nb_device.serial = serial
                update_needed = True
            
            if update_needed:
                nb_device.save()
                logger.info(f"Updated device: {device_name}")
            
            return nb_device
        
        # If not found by name, try by serial number
        if serial:
            nb_device = nb.dcim.devices.get(serial=serial)
            if nb_device:
                logger.info(f"Found existing device by serial: {serial}")
                
                # Update device with new information if needed
                update_needed = False
                if nb_device.name != device_name:
                    nb_device.name = device_name
                    update_needed = True
                # Only update device_type if current type is the generic "Meraki AP"
                if nb_device.device_type.id != device_type_id and nb_device.device_type.model == "Meraki AP":
                    nb_device.device_type = device_type_id
                    update_needed = True
                if nb_device.role.id != role_id:
                    nb_device.role = role_id
                    update_needed = True
                
                if update_needed:
                    nb_device.save()
                    logger.info(f"Updated device: {device_name}")
                
                return nb_device
        
        # If device doesn't exist anywhere, create a new one
        logger.info(f"Creating new device: {device_name}")
        device_data = {
            'name': device_name,
            'device_type': device_type_id,
            'role': role_id,
            'site': site_id,
            'status': status,
            'tags': tags
        }
        
        if serial:
            device_data['serial'] = serial
        if description:
            device_data['description'] = description
            
        return nb.dcim.devices.create(**device_data)
    
    except Exception as e:
        logger.error(f"Error getting or creating device {device_name}: {str(e)}")
        raise


def sync_to_netbox(networks, devices, netbox_url, netbox_token):
    """Sync Meraki network devices to Netbox"""
    logger.info(f"Syncing data to Netbox at {netbox_url}")
    nb = api(netbox_url, token=netbox_token)
    session = requests.Session()
    session.verify = False
    nb.http_session = session
    
    # Create a tag for Meraki-synced objects
    meraki_tag = get_or_create_tag(
        nb,
        tag_name="meraki-sync",
        tag_slug="meraki-sync",
        tag_description="Synced from Cisco Meraki"
    )
    
    # Create device role for AP
    ap_role = get_or_create_device_role(
        nb,
        name="Access Point", 
        tags=[meraki_tag.id]
    )
    
    # Process each device
    all_meraki_devices = []
    
    for network in networks:
        network_id = network['id']
        network_name = network['name']
        facility_id = extract_facility_id(network_name)
        
        if not facility_id:
            logger.warning(f"Could not extract facility ID from network name: {network_name}, skipping")
            continue
        
        logger.info(f"Processing network: {network_name} (Facility ID: {facility_id})")
        
        # Get all devices in network
        network_devices = devices.get(network_id, [])
        logger.info(f"Found {len(network_devices)} access points in network {network_name}")
        
        # Keep track of all Meraki devices for stale device removal
        all_meraki_devices.extend(network_devices)
        
        # Create/get site for this network
        site_name = network_name
        site = get_or_create_site(
            nb,
            name=site_name,
            facility_id=facility_id,
            description=f"Meraki Network: {network_name} (Organization: {network.get('org_name', 'Unknown')})",
            tags=[meraki_tag.id]
        )
        
        # Process each access point
        for device in tqdm(network_devices, desc=f"Processing devices in {network_name}"):
            # Use the client description as the device name
            device_name = device.get('description', device.get('id', 'Unknown'))
            # Client data doesn't have model - we'll use "Meraki AP" as default
            device_model = "Meraki AP"
            # Get MAC address and IP
            device_mac = device.get('mac', '')
            device_ip = device.get('ip', '')
            # Clients don't have serials, use the MAC address
            device_serial = device_mac.replace(':', '')
            
            # Create description with Meraki data
            device_description = f"Meraki Access Point\nNetwork: {network_name}\nMAC: {device_mac}\nIP: {device_ip}\nClient ID: {device.get('id', 'Unknown')}"
            
            # Truncate name if needed
            device_name = truncate_name(device_name)
            
            # Get or create device type
            device_type = get_or_create_device_type(
                nb,
                model=device_model,
                manufacturer_name="Cisco Meraki",
                tags=[meraki_tag.id]
            )
            
            # Try to get existing device
            try:
                # First try by serial number
                if device_serial:
                    nb_device = nb.dcim.devices.get(serial=device_serial)
                    if nb_device:
                        logger.info(f"Found existing device by serial: {device_serial}")
                        
                        # Update device with new information
                        update_needed = False
                        # Only update device_type if current type is the generic "Meraki AP"
                        if nb_device.device_type.id != device_type.id and nb_device.device_type.model == "Meraki AP":
                            nb_device.device_type = device_type.id
                            update_needed = True
                        if nb_device.role.id != ap_role.id:
                            nb_device.role = ap_role.id
                            update_needed = True
                        if nb_device.site.id != site.id:
                            nb_device.site = site.id
                            update_needed = True
                        if nb_device.name != device_name:
                            nb_device.name = device_name
                            update_needed = True
                        
                        if update_needed:
                            nb_device.save()
                            logger.info(f"Updated device: {device_name}")
                        
                        # Skip to IP handling
                        
                    else:
                        # Try by name and site
                        nb_device = nb.dcim.devices.get(name=device_name, site_id=site.id)
                        if nb_device:
                            logger.info(f"Found existing device by name and site: {device_name}")
                            
                            # Update serial if it doesn't match
                            if nb_device.serial != device_serial:
                                nb_device.serial = device_serial
                                nb_device.save()
                                logger.info(f"Updated serial for device: {device_name}")
                        else:
                            # Need to create a new device
                            nb_device = get_or_create_device(
                                nb=nb,
                                device_name=device_name,
                                device_type_id=device_type.id,
                                role_id=ap_role.id,
                                site_id=site.id,
                                status='active',
                                tags=[meraki_tag.id],
                                serial=device_serial,
                                description=truncate_description(device_description)
                            )
                            logger.info(f"Created new device: {device_name}")
                
                else:
                    # No serial number, try by name and site
                    nb_device = nb.dcim.devices.get(name=device_name, site_id=site.id)
                    if nb_device:
                        logger.info(f"Found existing device by name and site: {device_name}")
                    else:
                        # Create new device
                        nb_device = get_or_create_device(
                            nb=nb,
                            device_name=device_name,
                            device_type_id=device_type.id,
                            role_id=ap_role.id,
                            site_id=site.id,
                            status='active',
                            tags=[meraki_tag.id],
                            serial=device_serial,
                            description=truncate_description(device_description)
                        )
                        logger.info(f"Created new device: {device_name}")
                
            except RequestError as e:
                # Handle the case where device name already exists in the site
                if "Device name must be unique per site" in str(e):
                    # Make the name unique by appending a suffix
                    suffix = 1
                    while True:
                        unique_name = f"{device_name}-{suffix}"
                        try:
                            # Check if this name is available
                            if len(unique_name) > 64:
                                # Truncate again if needed
                                unique_name = f"{device_name[:60]}-{suffix}"
                            
                            nb_device = nb.dcim.devices.create(
                                name=unique_name,
                                device_type=device_type.id,
                                role=ap_role.id,
                                site=site.id,
                                status='active',
                                tags=[meraki_tag.id],
                                serial=device_serial,
                                description=truncate_description(device_description)
                            )
                            logger.info(f"Created new device with unique name: {unique_name}")
                            break
                        except RequestError as inner_e:
                            if "Device name must be unique per site" in str(inner_e):
                                suffix += 1
                            else:
                                # Re-raise if it's a different error
                                raise
                else:
                    # Re-raise if it's a different error
                    raise
            
            # Create interface if it doesn't exist
            interface_name = "LAN"  # Default interface name for APs
            try:
                interface = nb.dcim.interfaces.get(device_id=nb_device.id, name=interface_name)
                if not interface:
                    interface = nb.dcim.interfaces.create(
                        device=nb_device.id,
                        name=interface_name,
                        type="1000base-t",
                        mac_address=device_mac if device_mac else None,
                        tags=[meraki_tag.id]
                    )
                    logger.info(f"Created interface {interface_name} for device {device_name}")
                else:
                    logger.info(f"Found existing interface {interface_name} for device {device_name}")
            except Exception as e:
                logger.debug(f"Error getting interface {interface_name} for device {device_name}: {str(e)}")
                interface = nb.dcim.interfaces.create(
                    device=nb_device.id,
                    name=interface_name,
                    type="1000base-t",
                    mac_address=device_mac if device_mac else None,
                    tags=[meraki_tag.id]
                )
                logger.info(f"Created interface {interface_name} for device {device_name}")
            
            # Add IP address if available
            if device_ip:
                try:
                    ip_obj = get_or_create_ip_address(
                        nb,
                        ip_address=device_ip,
                        description=f"IP for {device_name} from Meraki",
                        tags=[meraki_tag.id],
                        interface_id=interface.id
                    )
                    
                    # Set as primary IP for the device
                    if ip_obj:
                        try:
                            # Update the device with this as primary IPv4
                            nb_device.primary_ip4 = ip_obj.id
                            nb_device.save()
                            logger.info(f"Set {ip_obj.address} as primary IP for device {device_name}")
                        except Exception as e:
                            logger.error(f"Error setting primary IP for device {device_name}: {str(e)}")
                            
                except Exception as e:
                    logger.error(f"Error creating IP address {device_ip} for {device_name}: {str(e)}")
    

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Sync Cisco Meraki access points to Netbox')
    parser.add_argument('--meraki-api-key', help='Cisco Meraki API key', default=os.environ.get('MERAKI_API_KEY'))
    parser.add_argument('--netbox-url', help='Netbox URL', default=os.environ.get('NETBOX_URL'))
    parser.add_argument('--netbox-token', help='Netbox API token', default=os.environ.get('NETBOX_TOKEN'))
    return parser.parse_args()

def main():
    """Main function to orchestrate the Meraki to Netbox sync"""
    args = parse_arguments()
    
    # Validate Meraki API key
    if not args.meraki_api_key:
        logger.error("Meraki API key must be provided either as an argument or environment variable")
        sys.exit(1)
    
    # Validate Netbox parameters
    if not args.netbox_url or not args.netbox_token:
        logger.error("Netbox URL and token must be provided either as arguments or environment variables")
        sys.exit(1)
    
    try:
        logger.info("Starting Cisco Meraki to Netbox sync")
        
        # Get all Meraki networks
        networks = get_meraki_networks(args.meraki_api_key)
        
        # Get all AP clients for each network
        network_devices = {}
        for network in networks:
            network_id = network['id']
            # Use the new function to get AP clients instead of devices
            ap_clients = get_ap_clients_in_network(args.meraki_api_key, network_id)
            if ap_clients:
                network_devices[network_id] = ap_clients
        
        # Sync to Netbox
        sync_to_netbox(networks, network_devices, args.netbox_url, args.netbox_token)
        
        logger.info("Cisco Meraki to Netbox sync completed successfully")
        
    except Exception as e:
        logger.error(f"Error during Cisco Meraki to Netbox sync: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
