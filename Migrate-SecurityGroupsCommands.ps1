.\Migrate-SecurityGroups.ps1 `
    -CsvPath "C:\TEMP\AccessEnum_output.csv" `
    -SourceDomain "source.domain.com" `
    -SourceDC "sourcedc.source.domain.com" `
    -TargetDomain "target.domain.com" `
    -TargetDC "targetdc.target.domain.com" `
    -TargetOU "OU=SecurityGroups,DC=target,DC=domain,DC=com" `
    -TestMode
