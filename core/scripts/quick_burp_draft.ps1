param(
    [Parameter(Mandatory=$true)]
    [string]$SourceDir,

    [Parameter(Mandatory=$true)]
    [string]$Target,

    [Parameter(Mandatory=$true)]
    [string]$VulnSlug,

    [string]$Style = 'butian',
    [string]$Title = '',
    [string]$BusinessImpact = ''
)

$env:PYTHONPATH = "C:\Users\Administrator\.agents\skills\hunter"

@"
from core.draft_generator import generate_submission_draft_from_burp
import json
result = generate_submission_draft_from_burp(r'''$SourceDir''', r'''$Target''', r'''$VulnSlug''', style=r'''$Style''', title=r'''$Title''', business_impact=r'''$BusinessImpact''')
print(json.dumps(result, ensure_ascii=False, indent=2))
"@ | python -
