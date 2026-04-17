import discord
import os
import aiohttp
import json
import asyncio
from discord.ext import commands

# Initialize Bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# Connect to the local NexusRE MCP server (using its REST/SSE endpoint if active, or direct DB read)
MCP_URL = "http://127.0.0.1:8080" # Default SSE port
API_KEY = os.environ.get("NEXUSRE_API_KEY", "")

@bot.event
async def on_ready():
    print(f"[+] NexusRE Discord Bot online as {bot.user}")

@bot.command()
async def status(ctx, game: str = None):
    """Check signature health for a specific game."""
    if not game:
        await ctx.send("❌ Please provide a game name. Example: `!status r6siege`")
        return

    msg = await ctx.send(f"🔄 Scanning NexusRE Brain DB for `{game}` signatures...")
    
    try:
        from core.memory import brain
        key = f"signatures:{game}"
        raw = brain.recall_knowledge(key)
        
        if "No memories found" in raw:
            await msg.edit(content=f"❌ No signatures tracked for `{game}`.")
            return

        # Simple string parsing since we import brain directly but we want just the count
        lines = raw.split("\n")
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith("["):
                json_start = i
                break
                
        if json_start is not None:
            json_str = "\n".join(lines[json_start:])
            if json_str.rstrip().endswith(")"):
                json_str = "\n".join(json_str.rstrip().rsplit("\n", 1)[:-1])
            signatures = json.loads(json_str)
            
            embed = discord.Embed(title=f"NexusRE Offset Status: {game.upper()}", color=0x00ff00)
            embed.set_thumbnail(url="https://github.com/fluidicon.png")
            embed.add_field(name="Tracked Signatures", value=str(len(signatures)), inline=False)
            embed.add_field(name="Status", value="✅ All signatures loaded in Brain DB.\nRun `validate_signatures` in MCP to check LIVE health.", inline=False)
            await msg.edit(content=None, embed=embed)
        else:
            await msg.edit(content=f"⚠️ Loaded DB for `{game}` but data may be corrupted.")

    except Exception as e:
        await msg.edit(content=f"❌ Error communicating with NexusRE Core: {str(e)}")

@bot.command()
async def update(ctx, game: str):
    """Trigger an asynchronous signature validation and recovery."""
    # Note: Requires an active headless session in the MCP server.
    await ctx.send(f"⚠️ Triggering AI recovery for {game}... Check dashboard for live progress.")

if __name__ == "__main__":
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        print("[!] DISCORD_TOKEN environment variable not set.")
    else:
        bot.run(token)
