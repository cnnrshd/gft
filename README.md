# gft

GFT - Apply Filters against Input (Generally)

## Filters

The goal of this tool is to apply some kind of filter against some kind of input and generate some kind of report. See filter types below for more specific ideas.

### Sysmon

The Sysmon filter (callable with `gft sysmon`) aims to perform several useful functions with a provided Sysmon config and log file. The primary goal is to report on the proper layering of a config file - proper is subjective, so this will allow you to see every event that matches a MITRE ATT&CK Technique ID and whether it would:

- Be tagged appropriately (before a dragnet rule)
- Be excluded

This is an alternative to the arduous process of modifying a config, running a test, gathering the data, sifting through WEL, not seeing the log, scanning the config to try to find conflicts, GOTO START.

Ultimately I plan on using this tool for automated testing of security logs and config files - pull logs from [Security Datasets](https://securitydatasets.com/introduction.html) and ensure that my configs hit the techniques used.

#### How to Use

1. Clone locally
2. (Optional but you should) make a virtual environment
3. Install the requirements
4. Run commands below

The repo contains some [test data](./test_data/), with a Sysmon config (Config is from my fork of [sysmon-modular](https://github.com/cnnrshd/sysmon-modular/blob/master/config_lists/default_list/default_list_config.xml)) and [Security Datasets log data for VBS Execution](https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-190518182022.html).

A major use case is seeing what techniques are being hit on in a config, and seeing the layering. I suggest using the `--named-only` flag for this: `python3 ./gft/main.py sysmon test --named-only ./test_data/sysmon-config.xml ./test_data/empire_launcher_vbs_2020-09-04160940.json`

For viewing filters, I suggest this command - I actually just used it to fix my Sysmon config since it wasn't properly tagging Line 73 in the Security Dataset log as T1059.005: `python3 ./gft/main.py sysmon test --named-only --filter-in '.*T1059.*' ./test_data/sysmon-config.xml ./test_data/empire_launcher_vbs_2020-09-04160940.json`

#### Notes

- Filtering does not currently support a RuleGroup with groupRelation="and", including it is very low on priority list since the same logic can be done with a Rule with groupRelation="and"

### Nmap

Not started. The goal is to be able to run nmap service probes against service banners to make developing nmap banners probes easier - grab a banner once (maybe from Shodan) and test it locally instead of repeatable modifying your nmap service probe file and scanning some poor server.
