# SysmonValidate

The script validates the sysmon.xml configuration file with the schema provided by the `sysmon.exe -m` command.
An audit is being conducted on:

1. The xml config version does not exceed the schema version
2. Correctness of the names of the configuration file options
```
      <option switch="a" name="ArchiveDirectory" argument="required" />
      <option name="CaptureClipboard" argument="none" />
      <option switch="d" name="DriverName" argument="required" />
      <option switch="dns" name="DnsQuery" argument="optional" rule="true" />
      <option switch="g" name="PipeMonitoring" argument="required" rule="true" forceconfig="true" />
      <option switch="h" name="HashAlgorithms" argument="required" />
      <option name="DnsLookup" argument="required" />
      <option switch="k" name="ProcessAccess" argument="required" rule="true" forceconfig="true" />
      <option switch="l" name="ImageLoad" argument="optional" rule="true" />
      <option switch="n" name="NetworkConnect" argument="optional" rule="true" />
      <option switch="r" name="CheckRevocation" argument="optional" rule="true" />
      <option name="FieldSizes" argument="required" />
```
3. Values of the groupRelation attribute of the RuleGroup element
4. Names of filtering events, e.g. `ProcessCreate`
5. Values of the onmatch attribute of the filtering events  `ProcessCreate onmatch="exclude"`
6. Sub-element data of the event element, e.g. `FileCreateTime`
```
      <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
      <data name="UtcTime" inType="win:UnicodeString" outType="xs:string" />
      <data name="ProcessGuid" inType="win:GUID" />
      <data name="ProcessId" inType="win:UInt32" outType="win:PID" />
```
7. Used filters of the data element `is,is not,contains,contains any,is any,contains all,excludes,excludes any, excludes all,begin with,not begin with,end with,not end with,less than,more than,image`

TODO:
1. Check the type data in the rules
2. Check characters outside the xml block
3. Get schema from sysmon `sysmon.exe -s`