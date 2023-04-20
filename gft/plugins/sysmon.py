import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from re import compile, match
from typing import Iterator

from config import config
from lxml import etree
from lxml.etree import Element, ElementTree
from typer import Argument, FileText, FileTextWrite, Option, Typer

console = config.console

app = Typer(rich_markup_mode="markdown")


# Event lookup list - no hashing required.
EVENT_LOOKUP = [
    None,  # 0 (not a valid Event ID)
    "ProcessCreate",
    "FileCreateTime",
    "NetworkConnect",
    None,  # 4 (Sysmon service state change, cannot be filtered)
    "ProcessTerminate",
    "DriverLoad",
    "ImageLoad",
    "CreateRemoteThread",
    "RawAccessRead",
    "ProcessAccess",
    "FileCreate",
    "RegistryEvent",
    "RegistryEvent",
    "RegistryEvent",
    "FileCreateStreamHash",
    None,  # 16 (Sysmon configuration change, cannot be filtered)
    "PipeEvent",
    "PipeEvent",
    "WmiEvent",
    "WmiEvent",
    "WmiEvent",
    "DnsQuery",
    "FileDelete",
    "ClipboardChange",
    "ProcessTampering",
    "FileDeleteDetected",
    "FileBlockExecutable",
    "FileBlockShredding",
]


@dataclass
class Filter:
    field: str  # ex. Image - used for lookup
    name: str  # ex. "technique_id=T1055"
    condition: str  # ex. "begin with"
    value: str  # ex. "C:\Temp" - what is filtered

    def passes(self, event: dict) -> bool:
        # event is a dict holding Sysmon event field and values
        # name is not needed
        # condition changes logic
        if self.condition == "is":
            return event.get(self.field) == self.value
        elif self.condition == "is any":
            return event.get(self.field) in self.value.split(";")
        elif self.condition == "is not":
            return not (event.get(self.field) == self.value)
        elif self.condition == "contains":
            return self.value in event.get(self.field)
        elif self.condition == "contains any":
            return any(val in event.get(self.field) for val in self.value.split(";"))
        elif self.condition == "contains all":
            return all(val in event.get(self.field) for val in self.value.split(";"))
        elif self.condition == "excludes":
            return self.value not in event.get(self.field)
        elif self.condition == "excludes any":
            return not any(
                val in event.get(self.field) for val in self.value.split(";")
            )
        elif self.condition == "excludes all":
            return all(
                val not in event.get(self.field) for val in self.value.split(";")
            )
        elif self.condition == "begin with":
            return event.get(self.field).startswith(self.value)
        elif self.condition == "end with":
            return event.get(self.field).endswith(self.value)
        elif self.condition == "not begin with":
            return not event.get(self.field).startswith(self.value)
        elif self.condition == "not end with":
            return not event.get(self.field).endswith(self.value)
        elif self.condition == "less than":
            return self.value < event.get(self.field)
        elif self.condition == "more than":
            return self.value > event.get(self.field)
        elif self.condition == "image":
            return self.value == event.get(self.field).split("\\")[-1]
        else:
            raise ValueError(f"Invalid value for Filter.condition: {self.condition}")


def _parse_filter_element(elem: Element) -> Filter:
    attribute_dict = dict(elem.attrib)
    field = elem.tag
    value = elem.text
    condition = attribute_dict.get("condition", "is")
    return Filter(
        field=field,
        name=attribute_dict.get("name", ""),
        condition=condition,
        value=value,
    )


@dataclass
class Rule:
    filter_relation: str  # valid types are "or" and "and"
    event_type: str  # ex. ImageLoad, ProcessCreate
    onmatch: str  # include or exclude
    number: int  # tracks the order of rules
    name: str  # name of rule or filter
    filters: list[Filter] = field(default_factory=list)

    def passes(self, event: dict) -> bool:
        """A filter function that determines if a provided event would pass this rule
        Note that "passing" is relative. This means being included by an include and
        being excluded by an exclude.

        Args:
            event (dict): A dictionary representing a Sysmon event from Windows Event Logs

        Returns:
            bool: True if the event would pass the filter(s)
        """
        if self.filter_relation == "or":
            return any(f.passes(event) for f in self.filters)
        return all(f.passes(event) for f in self.filters)


def _extract_sysmon_rules(config: FileText) -> dict:
    """Extracts sysmon rules, ensuring that they are numbered in order of precedence

    Args:
        config (FileText): A valid Sysmon Config

    Returns:
        dict: A dictionary with keys (EventType,FilterType) and values [Rule] - ex:
                {("CreateRemoteThread","include") : [Rule(filter_relation='or', event_type='CreateRemoteThread',
                    onmatch='include', number=1, filters=[Filter(field='SourceImage',
                    name='technique_id=T1055,technique_name=Process Injection', condition='begin with'
                    , value='C:\\')]]
                }
    """
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
                    filter_name = filter.get("name", "")
                    logging.debug(f"\tDiscovered explicit rule {filter_name}")
                    sub_filters = list()
                    for subfilter in filter:
                        sub_filters.append(_parse_filter_element(subfilter))
                    rule = Rule(
                        filter_relation=filter.get("groupRelation"),
                        event_type=event_type,
                        onmatch=onmatch,
                        number=rule_number,
                        name=filter_name,
                        filters=sub_filters,
                    )
                    logging.debug(f"\tFound rule: {rule}")
                else:
                    # implied rules have a groupRelation of or
                    filter_name = filter.get("name", "")
                    rule = Rule(
                        filter_relation="or",
                        event_type=event_type,
                        onmatch=onmatch,
                        number=rule_number,
                        name=filter_name,
                        filters=[_parse_filter_element(filter)],
                    )
                    logging.debug(f"\tFound implied rule: {rule}")
                rules.append(rule)
            rules_dict[(event_type, onmatch)] = rules
    return rules_dict


# Arguments/Options definitions
SYSMON_CONFIG: FileText = Argument(
    ..., help="Valid Sysmon Config to extract rules from"
)
WEL_LOGFILE: FileText = Argument(
    ...,
    help="JSONL of Windows Event Logs to test against, see "
    "[Security-Datasets](https://securitydatasets.com/introduction.html) for examples of valid JSONL files.",
)
OUTFILE: FileTextWrite = Option("-", help="File to output to.")


@app.command(name="rules", help="Extract rules from a sysmon config")
def rules(config: FileText = SYSMON_CONFIG):
    console.print(_extract_sysmon_rules(config))


def _rule_generator(rules: list[Rule], event: dict) -> Iterator[Rule]:
    """Simple generator that returns the first matching rule

    Args:
        rules (list[Rule]): List of rules to test against. Can be include or exclude
        event (dict): A Sysmon event

    Yields:
        Iterator[Rule]: Iterator that generates passing rules.
    """
    for rule in rules:
        if rule.passes(event):
            yield rule


@app.command(
    name="emulate",
    help="Emulate running a Sysmon config against a log file - Exclude all filtered events, set Event Name based on first-hit rule",
)
def emulate_sysmon(
    config: FileText = SYSMON_CONFIG,
    logfile: FileText = WEL_LOGFILE,
    outfile: FileTextWrite = OUTFILE,
):
    rules = _extract_sysmon_rules(config)
    for line in logfile:
        event = json.loads(line)
        # filter
        event_id = event.get("EventID")
        if event_id > len(EVENT_LOOKUP) - 1:
            continue
        event_type = EVENT_LOOKUP[event_id]
        # check includes
        try:
            include_rules: list[Rule] = rules[(event_type, "include")]
            if first_matching_rule := next(
                (rule for rule in _rule_generator(include_rules, event)), None
            ):
                event["RuleName"] = first_matching_rule.name
            else:
                continue
        except KeyError:  # No includes for this event type
            continue
        # check excludes
        try:
            exclude_rules = rules[(event_type, "exclude")]
            if first_matching_rule := next(
                (rule for rule in _rule_generator(exclude_rules, event)), None
            ):
                # it is excluded
                continue
        except KeyError:
            pass

        outfile.write(
            json.dumps(
                event,
                indent=None,
            )
            + "\n"
        )


class OutputFormat(str, Enum):
    json = "json"
    terminal = "terminal"


@app.command(name="test", help="Test a provided config against a provided log file")
def test(
    config: FileText = SYSMON_CONFIG,
    logfile: FileText = WEL_LOGFILE,
    overruled: bool = Option(
        False,
        help=":construction: WIP :construction: Output rule matches that were overruled"
        " - an unnamed rule hit before the named rule. Useful for detecting unorganized configs.",
    ),
    named_only: bool = Option(
        False, help="Only output Events that have at least one named rule"
    ),
    filter_in: str = Option(
        "",
        help="Regular Expression to filter for. This uses re.match,"
        " not str.contains, so you might need wild cards. Ex: --filter_in '.\*T1049.\*'",
    ),
):
    """
    Test the provided Sysmon config against a provided log file, with optional filtering options.

    Log files are parsed and outputted as a stream - one line at a time.
    """
    rules = _extract_sysmon_rules(config)
    pattern = compile(filter_in) if filter_in else None
    for line_num, line in enumerate(logfile, start=1):
        event = json.loads(line)
        # filter
        event_id = event.get("EventID")
        if event_id > 30:
            continue
        event_type = EVENT_LOOKUP[event_id]
        line_rule_list = list()
        # check includes
        try:
            include_rules: list[Rule] = rules[(event_type, "include")]
            for rule in include_rules:
                if rule.passes(event):
                    line_rule_list.append(rule)
        except KeyError:
            pass
        # check excludes
        try:
            exclude_rules = rules[(event_type, "exclude")]
            for rule in exclude_rules:
                if rule.passes(event):
                    line_rule_list.append(rule)
        except KeyError:
            pass
        if named_only:
            # check for named rules
            if not any(rule.name for rule in line_rule_list):
                continue
        if pattern:
            if not any(match(pattern, rule.name) for rule in line_rule_list):
                continue
        console.print(f"Line {line_num} hit on {len(line_rule_list)} rules:")
        [
            console.print(
                f"\t{rule.event_type}\t{rule.onmatch}\t#{rule.number}\t{rule.name}"
            )
            for rule in line_rule_list
        ]


@app.callback(invoke_without_command=True)
def main():
    console.print("Entered sysmon_main")
