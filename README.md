# gft

GFT - Apply Filters against Input

## Filters

The goal of this tool is to apply some kind of filter against some kind of input and generate some kind of report. See filter types below for more specific ideas.

### Sysmon

The Sysmon filter (callable with `gft sysmon`) aims to perform several useful functions with a provided Sysmon config and logfile. The primary goal is to report on the proper layering of a config file - proper is subjective, so this will allow you to see every event that matches a MITRE ATT&CK Technique ID and whether it would:

- Be tagged appropriately (before a dragnet rule)
- Be excluded

This is an alternative to the arduous process of modifying a config, running a test, gathering the data, sifting through WEL, not seeing the log, scanning the config to try to find conflicts, GOTO START.

#### Notes

- Filtering does not currently support a RuleGroup with groupRelation="and", including it is very low on priority list since the same logic can be done with a Rule with groupRelation="and"
