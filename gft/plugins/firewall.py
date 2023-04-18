from config import config
from typer import Typer

console = config.console

app = Typer()


@app.command()
def firewall_main():
    console.print("Entered firewall main")
