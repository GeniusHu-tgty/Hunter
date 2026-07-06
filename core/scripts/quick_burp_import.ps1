param(
    [Parameter(Mandatory=$true)]
    [string]$SourceDir,

    [Parameter(Mandatory=$true)]
    [string]$Target,

    [Parameter(Mandatory=$true)]
    [string]$VulnSlug,

    [string]$DestinationDir = "C:\Users\Administrator\.agents\skills\hunter\evidence\tool_output"
)

$env:PYTHONPATH = "C:\Users\Administrator\.agents\skills\hunter"

@"
from core.burp_import import import_burp_evidence
import json
result = import_burp_evidence(r'''$SourceDir''', r'''$Target''', r'''$VulnSlug''', r'''$DestinationDir''')
print(json.dumps(result, ensure_ascii=False, indent=2))
"@ | python -
