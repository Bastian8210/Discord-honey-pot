import discord
from discord.ext import commands
from discord.ui import Button, View
import socket
import os
import subprocess
import logging
import threading
import time
from collections import defaultdict
import random

import asyncio
from logging.handlers import SysLogHandler
import random
import requests



# Get the token from the environment variable
TOKEN = "Your bot token"

if TOKEN is None:
    raise ValueError("No token found in environment variable DISCORD_BOT_TOKEN.")

# Enable intents, especially message content
intents = discord.Intents.default()
intents.message_content = True  # Allow the bot to read messages

# Define bot prefix (e.g., !)
bot = commands.Bot(command_prefix="!", intents=intents)

# Setup logging to console
logging.basicConfig(level=logging.INFO)

# Path for the log file
LOG_FILE_PATH = "ip_management.log"
name = socket.gethostname()
# Tracking calls to each port per IP
port_calls_by_ip = defaultdict(lambda: defaultdict(list))
alert_cooldowns = defaultdict(lambda: 0)  # Tracks the cooldowns for IPs
recent_alerted_ips = set()  # Track recently alerted IPs
ALERT_CHANNEL_ID = "CHANNEL_ID"  # Channel to send alerts
ALERT_COOLDOWN_SECONDS = 10  # Cooldown between alerts



# Fake HTTP response (for example)
services = [
    "Apache HTTP Server", 
    "nginx", 
    "Microsoft-IIS/10.0", 
    "Lighttpd", 
    "Jetty", 
    "Tomcat", 
    "Node.js", 
    "Python SimpleHTTPServer", 
    "Cherokee", 
    "Hiawatha", 
    "Caddy", 
    "Boa", 
    "Zeus", 
    "Tengine", 
    "OpenResty", 
    "Varnish", 
    "Squid", 
    "ThousandEyes", 
    "Cloudflare", 
    "Haproxy", 
    "Traefik", 
    "Akamai", 
    "Fastly", 
    "NetScaler", 
    "LiteSpeed", 
    "WebLogic", 
    "WebSphere", 
    "Oracle HTTP Server", 
    "XAMPP", 
    "WAMP", 
    "MAMP", 
    "Waggle", 
    "Yaws", 
    "F5 BIG-IP", 
    "AWS Elastic Load Balancer"
]

# Randomly shuffle the services list
random.shuffle(services)

# Create the body of the response with the randomized services
service_list = "<ul>"
for service in services:
    service_list += f"<li>{service}</li>"
service_list += "</ul>"

# Update the FAKE_HTTP_RESPONSE with the randomized services
FAKE_HTTP_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    f"Content-Length: {len(service_list)}\r\n"
    "\r\n"
    f"{service_list}"
)
    


        
# Function to log actions to a file
async def log_ip_action(action, ip):
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(f"{action}: {ip}\n")  # Log action and IP to the file
        logging.info(f"{action}: {ip} logged to file.")

# Function to block an IP
async def block_ip(ip):
    try:
        # Command to block the IP using netsh
        subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name=Block IP {ip}', 
            'dir=in', 
            'action=block',
            f'remoteip={ip}',  # Specify the remote IP to block
            'protocol=any'     # Specify the protocol, can be any
        ], check=True)
        
        logging.info(f"Blocked IP: {ip}")

    
        # Log the action
        await log_ip_action("Blocked", ip)

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip}: {str(e)}")


# Function to unblock an IP
async def unblock_ip(ip):
    try:
        # Command to unblock the IP using netsh
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name="Block IP {0}"'.format(ip)], check=True)
        logging.info(f"Unblocked IP: {ip}")
        await log_ip_action("Unblocked", ip)  # Log the action
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to unblock IP {ip}: {str(e)}")

# Function to handle incoming connections in a separate thread
def handle_connection(sock, port):
    while True:
        try:
            # Accept a connection and get the client socket and address
            client_socket, addr = sock.accept()
            ip = addr[0]
            logging.info(f"Connection from {ip} on port {port}.")  # Log connection details

            # Simulate a fake service response (HTTP)
            logging.info(f"Sending fake HTTP response to {ip} on port {port}.")
            client_socket.sendall(FAKE_HTTP_RESPONSE.encode())  # Send fake HTTP response
            client_socket.shutdown(socket.SHUT_WR)  # Ensure that the response has been flushed
            # Allow the client to read the response and then close the socket
            time.sleep(1)  # Give it time to process before closing
            client_socket.close()

            # Track port calls by the IP
            current_time = time.time()
            port_calls_by_ip[ip][port].append(current_time)

            # Cleanup calls older than 1 second
            port_calls_by_ip[ip][port] = [t for t in port_calls_by_ip[ip][port] if current_time - t < 1]

            # Check for alert condition (10 different ports in 1 second)
            asyncio.run_coroutine_threadsafe(check_for_alert(ip, current_time), bot.loop)

        except Exception as e:
            logging.error(f"Error accepting connection on port {port}: {str(e)}")
            break

async def check_for_alert(ip, current_time):
    # Skip if the IP is still in cooldown period
    if alert_cooldowns.get(ip, 0) > current_time:
        return  # Skip if still in cooldown

    # Count how many different ports were pinged in the last second by the IP
    unique_ports = sum(1 for port, times in port_calls_by_ip.get(ip, {}).items() if times)

    # First, check if the IP scanned 4 or more ports within 1 second
    if unique_ports >= 4:
        # Set the cooldown for this IP to avoid repeating alerts in short time
        alert_cooldowns[ip] = current_time + ALERT_COOLDOWN_SECONDS

        # Skip if an alert was already sent recently for this IP
        if ip in recent_alerted_ips:
            return  # Skip if alert was already sent recently

        # Retrieve the channel to send the alert
        channel = bot.get_channel(ALERT_CHANNEL_ID)
        if channel:
            embed = discord.Embed(
                title=f"🚨 {name} 🚨", 
                description=f"**Suspicious activity detected!**\nIP **{ip}** has scanned 4+ ports in under 1 second.",
                color=0xFF5733  # A more vibrant red color
            )
            embed.set_author(
                name="Honeypot Security System", 
                icon_url="https://cdn-icons-png.flaticon.com/512/10158/10158285.png"  # Honeypot icon
            )
            embed.set_thumbnail(url="https://cdn-icons-png.flaticon.com/512/10158/10158285.png")  # Matching thumbnail

            embed.add_field(
                name="Details", 
                value=f"IP: {ip}\nThis IP has triggered a **potential attack** by scanning 4 or more ports in under 1 second.\n**Immediate action recommended.**",
                inline=False
            )
            embed.add_field(
                name="Next Steps", 
                value="1️⃣ Review the affected IP.\n2️⃣ Block the IP if confirmed malicious.\n3️⃣ Investigate server logs for further insights.",
                inline=True
            )

            # Create a view with buttons for blocking and unblocking the IP
            view = View()

            # Define the Block callback with an embed
            async def block_callback(interaction):
                # Block the IP
                await block_ip(ip)

                # Create an embed to notify about the block action
                block_embed = discord.Embed(
                    title="✅ IP Blocked",
                    description=f"The IP **{ip}** has been successfully blocked due to suspicious activity.",
                    color=0xFF5733  # Red color for blocking
                )
                block_embed.set_author(name="Honeypot Security System", icon_url="https://cdn-icons-png.flaticon.com/512/10158/10158285.png")
                block_embed.add_field(
                    name="Action Taken", 
                    value=f"IP **{ip}** has been blocked for scanning 4 or more ports in under 1 second.",
                    inline=False
                )

                # Send the embed and the response message
                await interaction.response.send_message(embed=block_embed, ephemeral=True)

            # Define the Unblock callback with an embed
            async def unblock_callback(interaction):
                # Unblock the IP
                await unblock_ip(ip)

                # Create an embed to notify about the unblock action
                unblock_embed = discord.Embed(
                    title="✅ IP Unblocked",
                    description=f"The IP **{ip}** has been successfully unblocked.",
                    color=0x33FF57  # Green color for unblocking
                )
                unblock_embed.set_author(name="Honeypot Security System", icon_url="https://cdn-icons-png.flaticon.com/512/10158/10158285.png")
                unblock_embed.add_field(
                    name="Action Taken", 
                    value=f"IP **{ip}** has been unblocked after review.",
                    inline=False
                )

                # Send the embed and the response message
                await interaction.response.send_message(embed=unblock_embed, ephemeral=True)

            # Add buttons to the view
            block_button = Button(label="Block IP", style=discord.ButtonStyle.danger)
            block_button.callback = block_callback  # Assign callback

            unblock_button = Button(label="Unblock IP", style=discord.ButtonStyle.success)
            unblock_button.callback = unblock_callback  # Assign callback

            view.add_item(block_button)
            view.add_item(unblock_button)

            # Send the embed with the buttons
            await channel.send(embed=embed, view=view)

            # Mark this IP as recently alerted to avoid repeating the alert
            recent_alerted_ips.add(ip)

    # Then, check if the IP scanned 30 or more ports per second
    if unique_ports >= 30:
        # Block the IP using netsh command
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name="Block IP {0}"'.format(ip)], check=True)

        # Send an embed for blocking the IP due to high port scans
        channel = bot.get_channel(ALERT_CHANNEL_ID)
        if channel:
            block_embed = discord.Embed(
                title="🚨 IP Blocked: High Port Scans 🚨", 
                description=f"IP **{ip}** has been blocked for scanning 30+ ports per second.",
                color=0xFF5733  # A more vibrant red color
            )
            block_embed.set_author(
                name="Honeypot Security System", 
                icon_url="https://cdn-icons-png.flaticon.com/512/10158/10158285.png"  # Honeypot icon
            )
            block_embed.set_thumbnail(url="https://cdn-icons-png.flaticon.com/512/10158/10158285.png")  # Matching thumbnail

            block_embed.add_field(
                name="Action Taken", 
                value=f"IP: {ip}\nThis IP has been blocked due to exceeding the threshold of 30 ports per second.",
                inline=False
            )

            await channel.send(embed=block_embed)



# Function to bind ports for the honeypot
async def bind_honeypot_ports(num_ports, port_start, port_end):
    open_sockets = []
    bound_ports = []
    failed_ports = []

    # Determine the ports to bind
    port_range = range(port_start, port_end + 1)
    if len(port_range) < num_ports:
        logging.error("Not enough ports in the specified range.")
        return False, "Not enough ports in the specified range.", bound_ports, failed_ports

    # Randomly select num_ports ports from the specified range
    ports_to_bind = random.sample(port_range, num_ports)

    try:
        # Create and bind sockets, skipping already-used ports
        for port in ports_to_bind:
            logging.info(f"Attempting to bind to port {port}...")
            honeypot_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            honeypot_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of address
            try:
                honeypot_socket.bind(("0.0.0.0", port))  # Bind to all interfaces
                honeypot_socket.listen(5)  # Allow up to 5 connections per port
                open_sockets.append(honeypot_socket)
                bound_ports.append(port)
                logging.info(f"Successfully bound and listening on port {port}.")
                
                # Start a new thread to handle incoming connections
                threading.Thread(target=handle_connection, args=(honeypot_socket, port), daemon=True).start()
            except socket.error as e:
                failed_ports.append(port)  # Skip ports that are already in use
                logging.warning(f"Failed to bind to port {port}: {e}")

        if bound_ports:
            # Send embed with success message (only showing number of bound ports)
            channel = bot.get_channel(ALERT_CHANNEL_ID)
            if channel:
                embed = discord.Embed(
                    title=f"✅ {name} ✅",
                    description=f"**Successfully bound to {len(bound_ports)} ports.**",
                    color=0x28A745  # Green check mark color
                )
                embed.set_author(
                    name="Honeypot Security System",
                    icon_url="https://cdn-icons-png.flaticon.com/512/10158/10158285.png"
                )
                embed.set_thumbnail(url="https://cdn-icons-png.flaticon.com/512/10158/10158285.png")

                embed.add_field(
                    name="Ports Bound",
                    value=f"Number of ports bound: **{len(bound_ports)}**",
                    inline=False
                )
                await channel.send(embed=embed)

            return True, f"Successfully bound to {len(bound_ports)} ports.", bound_ports, failed_ports
        else:
            return False, "No ports could be bound.", bound_ports, failed_ports
    except Exception as e:
        logging.error(f"Error in binding ports: {str(e)}")
        return False, f"Error: {str(e)}", bound_ports, failed_ports


# Define the command using the ! prefix
@bot.command(name="honey")
async def honey_command(ctx, num_ports: int, port_start: int, port_end: int):
    logging.info(f"Received command to bind {num_ports} ports from {port_start} to {port_end}.")
    success, message, bound_ports, failed_ports = await bind_honeypot_ports(num_ports, port_start, port_end)

    # Create the embed message
    embed = discord.Embed(title="Honeypot Status", description=message, color=0xFFD700)  # Honey-themed color (golden)

    # No longer showing bound ports in the message, just the count
    embed.add_field(name="Bound Ports Count", value=len(bound_ports))
    if failed_ports:
        embed.add_field(name="Failed Ports", value=', '.join(map(str, failed_ports)))

    await ctx.send(embed=embed)

# Command to manage IP actions (block/unblock)
@bot.command(name="manage_ip")
async def manage_ip_command(ctx, action: str, ip: str):
    if action.lower() == "block":
        await block_ip(ip)
        await ctx.send(f"IP {ip} has been blocked.")
    elif action.lower() == "unblock":
        await unblock_ip(ip)
        await ctx.send(f"IP {ip} has been unblocked.")
    else:
        await ctx.send("Invalid action. Please use 'block' or 'unblock'.")

# Event that runs when the bot is ready
@bot.event
async def on_ready():
    logging.info(f"Logged in as {bot.user.name} (ID: {bot.user.id})")
    print(f"Logged in as {bot.user.name} (ID: {bot.user.id})")

# Run the bot
bot.run(TOKEN)
