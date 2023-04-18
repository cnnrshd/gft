import logging
from dataclasses import dataclass, field

from config import config
from lxml import etree
from lxml.etree import Element, ElementTree
from typer import Argument, FileText, Option, Typer

console = config.console

app = Typer(rich_markup_mode="markdown")


@app.callback(invoke_without_command=True)
def main():
    console.print("Entered sysmon_main")


@dataclass
class Filter:
    field: str
    name: str
    condition: str
    value: str


def _parse_filter_element(elem: Element) -> Filter:
    attribute_dict = dict(elem.attrib)
    field = elem.tag
    value = elem.text
    return Filter(
        field=field,
        name=attribute_dict.get("name", ""),
        condition=attribute_dict.get("condition"),
        value=value,
    )


@dataclass
class Rule:
    filter_relation: str  # valid types are "or" and "and"
    event_type: str  # ex. ImageLoad, ProcessCreate
    onmatch: str  # include or exclude
    number: int  # tracks the order of rules
    filters: list[Filter] = field(default_factory=list)

    def passes(self, event: dict) -> bool:
        """A filter fuction that determines if a provided event would pass this rule
        Note that "passing" is relative. This means being included by an include and
        being excluded by an exclude.

        Args:
            event (dict): A dictionary representing a Sysmon event from Windows Event Logs

        Returns:
            bool: True if the event would pass the filter(s)
        """
        return True


def _extract_sysmon_rules(config: FileText) -> dict:
    tree: ElementTree = etree.parse(
        config, parser=etree.XMLParser(remove_blank_text=True, remove_comments=True)
    )
    rule_groups = tree.findall(".//RuleGroup")
    rules_dict = dict()
    for rule_group in rule_groups:
        for event in rule_group:
            onmatch = event.get("onmatch")
            event_type = event.tag
            rules = list()

            logging.debug(f"Working with {event_type} {onmatch}")
            for rule_number, filter in enumerate(event, start=1):
                if filter.tag == "Rule":
                    logging.debug(f"\tDiscovered explicit rule {filter.get('name','')}")
                    sub_filters = list()
                    for subfilter in filter:
                        sub_filters.append(_parse_filter_element(subfilter))
                    rule = Rule(
                        filter_relation=filter.get("groupRelation"),
                        event_type=event_type,
                        onmatch=onmatch,
                        number=rule_number,
                        filters=sub_filters,
                    )
                    logging.debug(f"\tFound rule: {rule}")
                else:
                    # implied rules have a groupRelation of or
                    rule = Rule(
                        filter_relation="or",
                        event_type=event_type,
                        onmatch=onmatch,
                        number=rule_number,
                        filters=[_parse_filter_element(filter)],
                    )
                    logging.debug(f"\tFound implied rule: {rule}")
                rules.append(rule)
            rules_dict[(event_type, onmatch)] = rules
    return rules_dict


@app.command(name="rules", help="Extract rules from a sysmon config")
def rules(config: FileText):
    console.print(_extract_sysmon_rules(config))


@app.command(name="test", help="Test a provided config against a provided log file")
def test(
    config: FileText = Argument(..., help="Valid Sysmon Config to extract rules from"),
    logfile: FileText = Argument(
        ...,
        help="""JSONL of Windows Event Logs to test against, see [Security-Datasets](https://securitydatasets.com/introduction.html) for examples of valid JSONL files.""",
    ),
):
    # get rules
    # read logs (one at a time? have a stream setting? might be good for large files)
    # filter non-sysmon logs out (do this while reading)
    # cross-reference eventid to eventtype
    # run rule against every filter in include & exclude eventtype - should be able to add a 'passes' property to a rule and filter by taht
    pass
