from config import config
from typer import Typer

console = config.console

app = Typer(rich_markup_mode="markdown")


@app.callback(invoke_without_command=True)
def firewall_main():
    console.print(
        f":construction: WIP :construction: Entered Firewall main - this section is WIP"
    )
