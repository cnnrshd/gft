"""GFT - Filters input, designed to detect conflicts, overlapping filters, whether data is filtered in or out"""
__author__ = "Connor Shade"
__email__ = "cnnrshd@gmail.com"

from rich.traceback import install as rich_log_install

rich_log_install(show_locals=True)
import logging

# TODO: Move "commands" to a "plugins" directory
#       and import everything from that directory + add it to typer automatically
from commands.main_app import app as main_app
from config import config
from plugins.firewall import app as app_firewall
from plugins.nmap import app as app_nmap
from plugins.sysmon import app as app_sysmon
from typer import Option

main_app.add_typer(app_firewall, name="firewall")
main_app.add_typer(app_nmap, name="nmap")
main_app.add_typer(app_sysmon, name="sysmon")


@main_app.callback()
def main_config(debug: bool = Option(False, help="Enable debugging")):
    config.debug = debug
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


def main():
    main_app()


if __name__ == "__main__":
    main()
