from typer import Typer
from utils.silly import get_program_name

app = Typer(
    rich_markup_mode="markdown",
    help=f"# {get_program_name()} Main",
)
