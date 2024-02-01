import os
from jinja2 import Environment, FileSystemLoader
import xml.etree.ElementTree as ET

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

if __name__ == "__main__":

    SCHEMA_DIR = os.path.join(os.getcwd(),"schemas")
    MODULES_DIR = os.path.join(os.getcwd(),"templates")
    SYSMON_CONFIG_NAME = "config"
    
    if not os.path.isdir("output"):
        os.mkdir("output")

    try:
        for file in os.listdir(SCHEMA_DIR):
            schema = SysmonSchema(os.path.join(SCHEMA_DIR, file))
            print(schema.binaryversion)
            print(schema.schemaversion)
            print(list(schema.events.keys()))
            schemaEvents = (schema.events.keys())            

            environment = Environment(loader=FileSystemLoader(MODULES_DIR), trim_blocks=True, lstrip_blocks=True)
            template = environment.get_template("config.xml.j2")

            configFilename = os.path.join("output",f"{schema.binaryversion}_{SYSMON_CONFIG_NAME}.xml")
            
            content = template.render(schemaversion=schema.schemaversion, modules_files=os.listdir(MODULES_DIR), event_schema=list(schema.events.keys()))
            print(content)
            
            with open(configFilename, "w") as obj:
                obj.write(content)
                
    except FileExistsError:
        print("ERROR - File not found")
    except Exception as e:
        print(f"ERROR - New exeception - {e}")
