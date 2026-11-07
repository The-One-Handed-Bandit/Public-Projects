from dotenv import load_dotenv
import os
import discord
from discord.ext import commands
from Modules.APIKEY import checker, string

load_dotenv()
KEY = os.getenv("Discord-bot-apikey")


intents = discord.Intents.default()
intents.message_content = True
Finder = commands.Bot(command_prefix="!", intents=intents)


@Finder.command()
async def ip(ctx):  
    if ctx.author.bot:
        return
    await ctx.send("What is the ip")
    try:
        grab = await Finder.wait_for('message')
        address = grab.content
        attribute = checker(address)
        await ctx.send(f"IP information[*] \n The Country code is ->{attribute.get("countryCode", 0)}"
                    f"\nThe ISP is ->{attribute.get('isp', 0)}\n" 
                    f"Abuse score is ->{attribute.get('abuseConfidenceScore', 0)}\n" 
                    f"For this ip ->{attribute.get('ipAddress', 0)}")

    except Exception as e:
        ctx.send(e)

@Finder.command()
async def link(ctx):
    if ctx.author.bot:
        return
    await ctx.send("What is the link")
    try:
        take = await Finder.wait_for('message')
        url = take.content
        hi = string(url)
        await ctx.send(f"\n[+] Detections: {hi['malicious']}/{hi['total']} \n File type: {hi['typel']} \n Content label: {hi['Content']}")
    except Exception as e:
        ctx.send(e)

Finder.run(KEY)