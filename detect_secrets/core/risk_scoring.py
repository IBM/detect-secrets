import re


BASE_SCORE = 50

HIGH_RISK_PATH_PATTERNS = [
    (r'\.github/workflows/', 15, 'ci-pipeline'),
    (r'terraform/', 15, 'infrastructure'),
    (r'helm/', 15, 'infrastructure'),
    (r'k8s/', 15, 'infrastructure'),
    (r'deploy/', 10, 'deployment'),
    (r'prod/', 15, 'production'),
    (r'\.env$', 10, 'dotenv'),
    (r'values\.yaml$', 10, 'helm-values'),
    (r'docker-compose', 10, 'docker'),
    (r'Dockerfile', 5, 'docker'),
]

LOW_RISK_PATH_PATTERNS = [
    (r'tests?/', -15, 'test'),
    (r'test_data/', -15, 'test'),
    (r'examples?/', -15, 'example'),
    (r'docs?/', -10, 'documentation'),
    (r'fixtures?/', -15, 'test-fixture'),
    (r'mock', -10, 'mock'),
    (r'sample', -10, 'sample'),
]

HIGH_RISK_SECRET_TYPES = [
    'Private Key',
    'AWS Access Key',
    'IBM Cloud IAM Key',
    'IBM COS HMAC Credentials',
    'Slack Token',
    'Stripe Access Key',
    'Twilio API Key',
]

SENSITIVE_KEYWORD_RE = re.compile(
    r'password|passwd|token|secret|apikey|api_key|client_secret|private_key',
    re.IGNORECASE,
)


def compute_risk(secret):
    """Compute risk metadata for a PotentialSecret.

    :type secret: detect_secrets.core.potential_secret.PotentialSecret
    :rtype: dict with keys: risk_score, risk_level, risk_reasons, context_tags
    """
    score = BASE_SCORE
    reasons = []
    tags = set()

    filename = secret.filename or ''

    for pattern, adjustment, tag in HIGH_RISK_PATH_PATTERNS:
        if re.search(pattern, filename):
            score += adjustment
            reasons.append('high-risk path: {}'.format(tag))
            tags.add(tag)

    for pattern, adjustment, tag in LOW_RISK_PATH_PATTERNS:
        if re.search(pattern, filename):
            score += adjustment
            reasons.append('low-risk path: {}'.format(tag))
            tags.add(tag)

    if secret.type in HIGH_RISK_SECRET_TYPES:
        score += 10
        reasons.append('high-risk secret type: {}'.format(secret.type))

    if SENSITIVE_KEYWORD_RE.search(filename):
        score += 5
        reasons.append('sensitive keyword in path')

    if secret.is_verified:
        score += 15
        reasons.append('verified secret')
        tags.add('verified')

    score = max(0, min(100, score))

    return {
        'risk_score': score,
        'risk_level': _score_to_level(score),
        'risk_reasons': reasons,
        'context_tags': sorted(tags),
    }


def _score_to_level(score):
    if score >= 75:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    return 'LOW'


def annotate_secrets(secrets_collection):
    """Apply risk scoring to all secrets in a SecretsCollection.

    :type secrets_collection: detect_secrets.core.secrets_collection.SecretsCollection
    """
    for filename in secrets_collection.data:
        for secret in secrets_collection.data[filename]:
            risk = compute_risk(secret)
            secret.risk_score = risk['risk_score']
            secret.risk_level = risk['risk_level']
            secret.risk_reasons = risk['risk_reasons']
            secret.context_tags = risk['context_tags']
