import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.risk_scoring import annotate_secrets
from detect_secrets.core.risk_scoring import compute_risk
from testing.factories import potential_secret_factory
from testing.factories import secrets_collection_factory


class TestComputeRisk:

    def test_baseline_score(self):
        secret = potential_secret_factory(filename='src/app.py')
        result = compute_risk(secret)
        assert result['risk_score'] == 50
        assert result['risk_level'] == 'MEDIUM'

    @pytest.mark.parametrize(
        'filename, min_score',
        [
            ('deploy/config.yaml', 60),
            ('prod/secrets.env', 65),
            ('terraform/main.tf', 65),
            ('.github/workflows/ci.yml', 65),
            ('helm/values.yaml', 65),
            ('k8s/deployment.yaml', 65),
        ],
    )
    def test_high_risk_paths_increase_score(self, filename, min_score):
        secret = potential_secret_factory(filename=filename)
        result = compute_risk(secret)
        assert result['risk_score'] >= min_score
        assert len(result['risk_reasons']) > 0

    @pytest.mark.parametrize(
        'filename, max_score',
        [
            ('tests/test_app.py', 40),
            ('test/test_app.py', 40),
            ('docs/example.md', 45),
            ('examples/demo.py', 40),
            ('fixtures/data.json', 40),
        ],
    )
    def test_low_risk_paths_decrease_score(self, filename, max_score):
        secret = potential_secret_factory(filename=filename)
        result = compute_risk(secret)
        assert result['risk_score'] <= max_score

    def test_high_risk_secret_type(self):
        secret = potential_secret_factory(
            type_='Private Key',
            filename='src/app.py',
        )
        result = compute_risk(secret)
        assert result['risk_score'] == 60
        assert 'high-risk secret type: Private Key' in result['risk_reasons']

    def test_verified_secret_increases_score(self):
        secret = PotentialSecret(
            'type', 'src/app.py', 'secret',
            lineno=1, is_verified=True,
        )
        result = compute_risk(secret)
        assert result['risk_score'] == 65
        assert 'verified' in result['context_tags']

    def test_sensitive_keyword_in_path(self):
        secret = potential_secret_factory(filename='config/password.ini')
        result = compute_risk(secret)
        assert result['risk_score'] == 55
        assert 'sensitive keyword in path' in result['risk_reasons']

    def test_score_clamped_to_range(self):
        secret = potential_secret_factory(
            type_='Private Key',
            filename='prod/deploy/terraform/.env',
        )
        result = compute_risk(secret)
        assert 0 <= result['risk_score'] <= 100

    def test_risk_level_high(self):
        secret = potential_secret_factory(
            type_='Private Key',
            filename='prod/deploy/values.yaml',
        )
        result = compute_risk(secret)
        assert result['risk_level'] == 'HIGH'

    def test_risk_level_low(self):
        secret = potential_secret_factory(filename='tests/fixtures/mock.py')
        result = compute_risk(secret)
        assert result['risk_level'] == 'LOW'

    def test_context_tags_populated(self):
        secret = potential_secret_factory(filename='deploy/config.yaml')
        result = compute_risk(secret)
        assert 'deployment' in result['context_tags']

    def test_multiple_tags(self):
        secret = potential_secret_factory(filename='prod/deploy/config.yaml')
        result = compute_risk(secret)
        assert 'production' in result['context_tags']
        assert 'deployment' in result['context_tags']


class TestAnnotateSecrets:

    def test_annotates_collection(self):
        collection = secrets_collection_factory(
            secrets=[
                {'filename': 'deploy/app.py', 'secret': 'abc'},
                {'filename': 'tests/test.py', 'secret': 'def'},
            ],
        )
        annotate_secrets(collection)

        for filename in collection.data:
            for secret in collection.data[filename]:
                assert secret.risk_score is not None
                assert secret.risk_level is not None
                assert isinstance(secret.risk_reasons, list)
                assert isinstance(secret.context_tags, list)

    def test_annotated_secrets_appear_in_json(self):
        collection = secrets_collection_factory(
            secrets=[{'filename': 'prod/app.py', 'secret': 'abc'}],
        )
        annotate_secrets(collection)

        for secret in collection.data['prod/app.py']:
            output = secret.json()
            assert 'risk_score' in output
            assert 'risk_level' in output
            assert 'risk_reasons' in output
            assert 'context_tags' in output


class TestRiskScoringOptIn:

    def test_no_risk_metadata_by_default(self):
        secret = potential_secret_factory()
        output = secret.json()
        assert 'risk_score' not in output
        assert 'risk_level' not in output
        assert 'risk_reasons' not in output
        assert 'context_tags' not in output

    def test_risk_metadata_present_after_annotation(self):
        secret = potential_secret_factory(filename='deploy/app.py')
        risk = compute_risk(secret)
        secret.risk_score = risk['risk_score']
        secret.risk_level = risk['risk_level']
        secret.risk_reasons = risk['risk_reasons']
        secret.context_tags = risk['context_tags']

        output = secret.json()
        assert output['risk_score'] >= 60
        assert output['risk_level'] in ('LOW', 'MEDIUM', 'HIGH')
