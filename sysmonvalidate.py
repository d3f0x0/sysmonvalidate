import xml.etree.ElementTree as ET
import argparse

class ConfigError(Exception):
    pass


class SysmonSchema:
    """
    The SysmonSchema class represents an object for parsing and validating the Sysmon schema from an XML file.

    Attributes:
    - filepath (str): The path to the XML file containing the Sysmon schema.
    - tree (xml.etree.ElementTree.ElementTree): An ElementTree object for parsing the XML schema.
    - root (xml.etree.ElementTree.Element): The root element of the XML schema.
    - schemaversion (str): The version of the Sysmon schema.
    - binaryversion (str): The version of the Sysmon binary file (if applicable).
    - filters (list): List of filters from the schema.
    - events (dict): Dictionary of events and their attributes from the schema.
    - options (list): List of configuration options from the schema.

    Methods:
    - __init__(self, filepath, binary=False): Constructor of the class. Initializes the object attributes by parsing the XML schema.
    - generate_schema_from_binary(self, filepath): Method to generate an XML schema from a Sysmon binary file.
    - get_schema_events(self) -> dict: Method to retrieve a dictionary of events and their attributes from the schema.
    - get_schema_options(self) -> list: Method to retrieve a list of configuration options from the schema.
    - get_schema_filters(self) -> list: Method to retrieve a list of filters from the schema.

    Example usage:
    ```python
    schema = SysmonSchema('schema.xml')
    print(f"Sysmon Schema Version: {schema.schemaversion}")
    print(f"Schema Events: {schema.events}")
    ```
    """
    def __init__(self, filepath):
        self.filepath = filepath

        try:
            self.tree = ET.parse(self.filepath)
            self.root = self.tree.getroot()
        except FileNotFoundError:
            raise ConfigError(f"ERROR: File not found: {self.filepath}")
        except ET.ParseError as e:
            raise ConfigError(f"ERROR: Error while parsing XML: {e}")

        self.schemaversion = self.root.attrib['schemaversion']
        self.binaryversion = self.root.attrib['binaryversion']
        self.filters = self.get_schema_filters()
        self.events = self.get_schema_events()
        self.options = self.get_schema_options()

    def get_schema_events(self) -> dict:
        """
        Get schema events with data and attributes
        """
        # name="SYSMONEVENT_CREATE_PROCESS" value="1" level="Informational" template="Process Create"
        # rulename="ProcessCreate" ruledefault="include" version="5"

        events_attrib = {}
        for event in self.root.iter('event'):

            event_name = event.get('rulename', None)
            # print(event_name)
            if event_name not in events_attrib:
                events_attrib[event_name] = {}

            for event_attrib in event.iter('data'):
                events_attrib[event_name][event_attrib.attrib['name']] = {
                    'inType': event_attrib.attrib['inType'],
                    'outType': event_attrib.attrib.get('outType', None)}

        return events_attrib

    def get_schema_options(self) -> list:
        """
        Get schema options

        :param:
        :return: list with options for configuration file
        """

        option_attrib = []
        for option in self.root.iter('option'):

            # nonconfig used for cli
            if option.attrib.get('noconfig'):
                continue

            option_attrib.append(option.attrib['name'])

        return option_attrib


    def get_schema_filters(self) -> list:
        schemafilter = self.root.find('.//configuration//filters')
        return schemafilter.text.split(',') if schemafilter is not None else []


def get_next_object(root: ET.ElementTree):
    """
    Utility function to retrieve the next XML element after a 'RuleGroup' within the XML structure.

    Args:
    - root (xml.etree.ElementTree.Element): The root element of the XML structure.

    Returns:
    - xml.etree.ElementTree.Element: The next XML element after the 'RuleGroup' if found, otherwise an empty string.

    Example usage:
    ```python
    rule_group = root.find('.//EventFiltering//RuleGroup')
    next_element = get_next_object(rule_group)
    ```
    """

    found_rule_group = False
    next_element_after_rule_group = ''
    for child in root.iter():
        if found_rule_group:
            next_element_after_rule_group = child
            break
        if child.tag == 'RuleGroup':
            found_rule_group = True
    return next_element_after_rule_group


if "__main__" == __name__:
    parser = argparse.ArgumentParser(description='Validate configuration against Sysmon schema.')
    parser.add_argument('config_file', help='Path to the configuration file')
    parser.add_argument('schema_file', help='Path to the Sysmon schema file')
    
    args = parser.parse_args()

    # Open config xml
    try:
        tree = ET.parse(args.config_file)
        root = tree.getroot()
    except FileNotFoundError:
        raise ConfigError(f"ERROR: File not found: {args.config_file}")
    except ET.ParseError as e:
        raise ConfigError(f"ERROR: Error while parsing XML: {e}")


    # Get sysmon schema
    schema = SysmonSchema(args.schema_file)

    # Check The configuration version is higher than the schema version
    config_schemaversion = float(root.attrib['schemaversion'])
    if config_schemaversion > float(schema.schemaversion):
        raise ConfigError(f"The configuration version is higher than the schema version: "
                          f"{config_schemaversion} > {schema.schemaversion}")

    # Get config options without EventFiltering
    config_options = [elem.tag for elem in root if elem.tag != 'EventFiltering']

    # Check Correctness of the names of the configuration file options
    for options in config_options:
        if options not in schema.get_schema_options():
            raise ConfigError(f"Correctness of the names of the configuration file options.\nSysmon -> "
                              f"ERROR: {options}\n")

    rule_group_element = root.findall(".//EventFiltering//RuleGroup")

    # Check into rule group
    for rulegroup in rule_group_element:
        next_object = get_next_object(rulegroup)

        # Check Values of the groupRelation attribute of the RuleGroup element
        if rulegroup.attrib['groupRelation'] not in ['and', 'or']:
            raise ConfigError(f"Values of the groupRelation attribute of the RuleGroup element.\n"
                              f"RuleGroup -> groupRelation: {next_object}\n")

        # Check events type filtering
        for objectrulegroup in rulegroup.findall(f".//{next_object.tag}"):

            # Check Names of filtering events
            if objectrulegroup.tag not in schema.events:
                raise ConfigError(f"Names of filtering events.\nRuleGroup -> ERROR: {next_object.tag}")

            # Check Values of the onmatch attribute of the filtering events
            if objectrulegroup.attrib['onmatch'] not in ['exclude', 'include']:
                raise ConfigError(f"Values of the onmatch attribute of the filtering events\nRuleGroup -> {next_object.tag} -> onmatch")

            flagRuleName = False
            for rule in objectrulegroup.iter():
                if not flagRuleName:
                    flagRuleName = True
                    continue
                
                if rule.tag == "Rule":
                    if rulegroup.attrib['groupRelation'] not in ['and', 'or']:
                        raise ConfigError(f"Values of the groupRelation attribute of the Rule element.\n"
                              f"Rule -> groupRelation: {next_object}\n")
                    continue

                # Sub-element data of the event element
                if rule.tag not in schema.events[next_object.tag] and rule.tag != "Rule":
                    raise ConfigError(f"Sub-element data of the event element\nRuleGroup -> {next_object.tag} -> ERROR: {rule.tag} = {rule.text}")

                # Used filters of the data element
                if not "condition" in rule.attrib:
                    raise ConfigError(f"Elements without condition.\n {next_object.tag} -> {rule.tag} -> {rule.text}")
                
                if rule.attrib['condition'] not in schema.filters :
                    raise ConfigError(f"Used filters of the data element.\nRuleGroup -> {next_object.tag} -> {rule.tag} -> {rule.attrib['condition']} "
                                      f"= {rule.text}")

    print("SUCCESS")