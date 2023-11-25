import xml.etree.ElementTree as ET
from typing import NamedTuple

class ConfigError(Exception):
    def __init__(self, msg):
        # print(msg)
        pass

class SchemaEventDataAttrib(NamedTuple):
    name: str
    inType: str
    outType: str


class SchemaFilters(NamedTuple):
    filters: list


class SysmonSchema:
    """
    Used:
    parse_schema = SysmonSchema(filepath='schema.xml')

    schema_events = parse_schema.get_schema_events()
    schema_options = parse_schema.get_schema_options()
    schema_filters = parse_schema.get_schema_filters()

    print(schema_filters)
    print(schema_options)
    print(schema_events)
    """

    def __init__(self, filepath):
        self.filepath = filepath
        self.tree = ET.parse(self.filepath)
        self.root = self.tree.getroot()
        self.schemaversion = self.root.attrib['schemaversion']
        self.binaryversion = self.root.attrib['binaryversion']
        self.filters = self.get_schema_filters()
        self.events = self.get_schema_events()
        self.options = self.get_schema_options()


    def get_schema_events(self) -> dict:
        """
        Get schema events with data and attributes
        :return dict{NameEventConfigurationFile:[SchemaEventDataAttrib, ..., n]}
        """
        # name="SYSMONEVENT_CREATE_PROCESS" value="1" level="Informational" template="Process Create"
        # rulename="ProcessCreate" ruledefault="include" version="5"

        events_attrib = {}
        for event in self.root.iter('event'):

            event_name = event.get('rulename', None)
            # print(event_name)
            if event_name not in events_attrib.keys():
                events_attrib[event_name] = {}

            for event_attrib in event.iter('data'):
                events_attrib[event_name][event_attrib.attrib['name']] = {}
                if 'outType' in event_attrib.attrib:
                    events_attrib[event_name][event_attrib.attrib['name']]['inType']=event_attrib.attrib['inType']
                    events_attrib[event_name][event_attrib.attrib['name']]['outType'] = event_attrib.attrib['outType']
                else:
                    events_attrib[event_name][event_attrib.attrib['name']]['inType']=event_attrib.attrib['inType']
                    events_attrib[event_name][event_attrib.attrib['name']]['outType'] = None

        # print(events_attrib)
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
            if 'noconfig' in option.attrib:
                continue

            option_attrib.append(option.attrib['name'])

        return option_attrib

    def get_schema_filters(self) -> list:
        for schemafilter in self.root.iter('filters'):
            return schemafilter.text.split(',')


class ConfigSchema:

    def __init__(self):
        self.schemaversion = ''

def get_next_object(root):
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
    tree = ET.parse('config.xml')
    root = tree.getroot()

    # Get sysmon schema
    schema = SysmonSchema('schema.xml')

    # Get schemaversion
    config_schemaversion = root.attrib['schemaversion']

    # Get config options without EventFiltering
    config_options = [elem.tag for elem in root if elem.tag != 'EventFiltering']

    # Check config options
    for options in config_options:
        if options not in schema.get_schema_options():
            raise ConfigError(f"Sysmon -> {options}")

    rule_group_element = root.findall(".//EventFiltering//RuleGroup")

    # Check into rule group
    for rulegroup in rule_group_element:
        next_object = get_next_object(rulegroup)

        # Check groupRelation
        if rulegroup.attrib['groupRelation'] not in ['and', 'or']:
            raise ConfigError(f"RuleGroup -> groupRelation: {next_object}")

        # Check rules filtering
        for objectrulegroup in rulegroup.findall(f".//{next_object.tag}"):

            # Check onmatch
            if objectrulegroup.attrib['onmatch'] not in ['exclude', 'include']:
                raise ConfigError(f"RuleGroup -> {next_object.tag} -> onmatch")

            flagRuleName = False
            for rule in objectrulegroup.iter():
                if not flagRuleName:
                    flagRuleName = True
                    continue

                #Check rule name
                if rule.tag not in schema.events[next_object.tag]:
                    raise ConfigError(f"RuleGroup -> {next_object.tag} -> {rule.tag} = {rule.text}")


                # Check rule condition
                if rule.attrib['condition'] not in schema.filters:
                    raise ConfigError(f"RuleGroup -> {next_object.tag} -> {rule.tag} -> {rule.attrib['condition']} "
                                      f"= {rule.text}")

