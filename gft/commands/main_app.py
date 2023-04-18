from importlib.resources import read_text
from random import choice

import data as gft_data
from rich import print as pprint
from rich.markdown import Markdown
from typer import Option, Typer

app = Typer(rich_markup_mode="markdown")


def _get_name_segment(letter: str) -> str:
    file_text = read_text(gft_data, f"{letter}.txt")
    return choice(file_text.split("\n"))


@app.callback(invoke_without_command=True)
def main():
    pprint(
        Markdown(
            f"# {_get_name_segment('g')} {_get_name_segment('f')} {_get_name_segment('t')}"
        )
    )
