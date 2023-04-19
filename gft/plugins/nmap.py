from config import config
from typer import Typer

console = config.console

app = Typer(rich_markup_mode="markdown")


@app.callback(invoke_without_command=True)
def nmap_main():
    console.print(
        ":construction: WIP :construction: Entered nmap main - this section is WIP"
    )
