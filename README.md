# migrate-domain-security-groups-and-members
This will process the Access Enumeration report from the source domain Net Share and create the Security Groups and Members in the Target domain.

Example Use Case:

You need to move a Windows File Server from one Active Directory domain to another and maintain access to the file shares, and are doing so in an enviroment for which a domain trust relationship exists. You have already copied or otherwise recreated your users from the source to the target directories using the same SamAccountName - but have not copied or migrated your security groups and members - or you have paritially created the security groups and members and need to reconcile.

This script will ignore all security group members whos name cannot be resolved or otherwise displays the SIDS id instead of their username. It will also ignore the built in security groups such as "NT AUTHORITY\*" -or  "BUILTIN\*" -or  "Administrators" -or "Users" -or "Everyone".

Directions:

1. Run the [Sysinternals AccessEnum](https://learn.microsoft.com/en-us/sysinternals/downloads/accessenum) on your source file server aginst on your drive containg the net shares and save the report to a directory with the migration scripts. Make sure to run the AccessEnum with a source domain account that has full permissions to read all security info on the source drive and net share locations.
2. Update your enviroment variables in the Migrate-SecurityGroupsCommands.ps1 to reflect your own source and target domain info and path to the AccessEnum csv file.
3. Dry Run the Migrate-SecurityGroupsCommands.ps1 from Powershell. It will prompt you for your source and target Active Directory login credentials necessary to read from the source domain, and write to the target. Use the -TestMode switch to do a dry run and review the output and missing security group and users reports located in the same directoy as the scripts.
4. Run the script again removing the -TestMode to write the Security Groups and Members to your target domain directory.

As always with anything out in the open, USE AT YOUR OWN RISK.

