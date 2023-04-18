from config import config
from typer import Typer

console = config.console

app = Typer()


@app.command()
def nmap_main():
    console.print("Entered nmap main")
