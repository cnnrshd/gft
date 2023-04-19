from importlib.resources import read_text
from random import choice

import data as gft_data


def _get_name_segment(letter: str) -> str:
    """Returns a random word from [letter].txt

    Args:
        letter (str): The letter to pull a word from

    Returns:
        str: Something like "General" or "Tyrannosaurus"
    """
    file_text = read_text(gft_data, f"{letter}.txt")
    return choice(file_text.split("\n"))


def get_program_name() -> str:
    """Returns some combination of words that start with G, F, and T

    Returns:
        str: A string described by the regex G[a-z]+ F[a-z]+ T[a-z]+
    """
    return f"{_get_name_segment('g')} {_get_name_segment('f')} {_get_name_segment('t')}"
