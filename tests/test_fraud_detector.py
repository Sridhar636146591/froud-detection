"""
Unit tests for fraud_detector.py
Tests the FraudDetector class rule scoring and ML model.
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock


class TestFraudDetectorInit:
    """Test that FraudDetector initializes correctly."""

    def test_income_threshold(self):
        from fraud_detector import FraudDetector
        fd = FraudDetector()
        assert fd.income_threshold == 300000

    def test_scheme_income_limits_exist(self):
        from fraud_detector import FraudDetector
        fd = FraudDetector()
        assert 'PM-KISAN' in fd.scheme_income_limits
        assert 'Ayushman Bharat' in fd.scheme_income_limits

    def test_feature_names_count(self):
        from fraud_detector import FraudDetector
        assert len(FraudDetector.FEATURE_NAMES) == 7


def _make_detector():
    from fraud_detector import FraudDetector
    return FraudDetector()


DB_PATCHES = [
    patch('database.check_duplicate_aadhaar', return_value=0),
    patch('database.check_phone_name_mismatch', return_value=False),
    patch('database.get_applications_by_phone', return_value=0),
    patch('database.get_similar_addresses', return_value=0),
    patch('database.get_applications_count_by_phone', return_value=0),
    patch('database.get_recent_applications_by_phone', return_value=0),
]


class TestRuleScoring:
    """Test the rule-based scoring component with mocked DB calls."""

    def test_clean_application_low_score(self):
        """A clean, valid application should score low."""
        fd = _make_detector()
        with patch('database.check_duplicate_aadhaar', return_value=0), \
             patch('database.check_phone_name_mismatch', return_value=False), \
             patch('database.get_applications_by_phone', return_value=0), \
             patch('database.get_similar_addresses', return_value=0), \
             patch('database.get_applications_count_by_phone', return_value=0), \
             patch('database.get_recent_applications_by_phone', return_value=0):
            score, reasons = fd.calculate_rule_score(
                name='Ravi Kumar',
                aadhaar='123456789012',
                phone='9876543210',
                income=150000,
                address='12 MG Road Bangalore Karnataka',
                scheme='PM-KISAN',
                age=40,
                gender='Male',
                district='Bangalore Rural'
            )
        assert score < 40, f"Clean application scored too high: {score}"

    def test_duplicate_aadhaar_adds_score(self):
        """Duplicate Aadhaar should add 40 points."""
        fd = _make_detector()
        with patch('database.check_duplicate_aadhaar', return_value=2), \
             patch('database.check_phone_name_mismatch', return_value=False), \
             patch('database.get_applications_by_phone', return_value=0), \
             patch('database.get_similar_addresses', return_value=0), \
             patch('database.get_applications_count_by_phone', return_value=0), \
             patch('database.get_recent_applications_by_phone', return_value=0):
            score, reasons = fd.calculate_rule_score(
                name='Fraud Person',
                aadhaar='111111111111',
                phone='9000000001',
                income=100000,
                address='Some Valid Address Near Market Area',
                scheme='Other',
                age=30
            )
        assert score >= 40
        assert any('Duplicate' in r for r in reasons)

    def test_invalid_aadhaar_format_adds_score(self):
        """Invalid Aadhaar (not 12 digits) should add score."""
        fd = _make_detector()
        with patch('database.check_duplicate_aadhaar', return_value=0), \
             patch('database.check_phone_name_mismatch', return_value=False), \
             patch('database.get_applications_by_phone', return_value=0), \
             patch('database.get_similar_addresses', return_value=0), \
             patch('database.get_applications_count_by_phone', return_value=0), \
             patch('database.get_recent_applications_by_phone', return_value=0):
            score, reasons = fd.calculate_rule_score(
                name='Test User',
                aadhaar='12345',
                phone='9876543210',
                income=100000,
                address='12 Market Road Pune Maharashtra Area',
                scheme='Other',
                age=30
            )
        assert score >= 35
        assert any('Aadhaar' in r or 'aadhaar' in r.lower() for r in reasons)

    def test_high_income_adds_score(self):
        """Income above threshold should add points."""
        fd = _make_detector()
        with patch('database.check_duplicate_aadhaar', return_value=0), \
             patch('database.check_phone_name_mismatch', return_value=False), \
             patch('database.get_applications_by_phone', return_value=0), \
             patch('database.get_similar_addresses', return_value=0), \
             patch('database.get_applications_count_by_phone', return_value=0), \
             patch('database.get_recent_applications_by_phone', return_value=0):
            score, reasons = fd.calculate_rule_score(
                name='Rich Person',
                aadhaar='123456789012',
                phone='9876543210',
                income=500000,
                address='12 MG Road Bangalore Karnataka Market Area',
                scheme='PM-KISAN',
                age=40
            )
        assert score >= 20

    def test_underage_old_age_pension_rejected(self):
        """Person < 60 applying for Old Age Pension should be flagged."""
        fd = _make_detector()
        with patch('database.check_duplicate_aadhaar', return_value=0), \
             patch('database.check_phone_name_mismatch', return_value=False), \
             patch('database.get_applications_by_phone', return_value=0), \
             patch('database.get_similar_addresses', return_value=0), \
             patch('database.get_applications_count_by_phone', return_value=0), \
             patch('database.get_recent_applications_by_phone', return_value=0):
            score, reasons = fd.calculate_rule_score(
                name='Young Person',
                aadhaar='123456789012',
                phone='9876543210',
                income=100000,
                address='12 MG Road Bangalore Karnataka Market',
                scheme='Old Age Pension',
                age=35
            )
        assert score >= 15
        assert any('age' in r.lower() or 'Age' in r for r in reasons)


class TestMLMetrics:
    """Test the get_ml_metrics() method produces valid output."""

    def test_metrics_structure(self):
        from fraud_detector import FraudDetector
        fd = FraudDetector()
        metrics = fd.get_ml_metrics()
        assert 'accuracy' in metrics
        assert 'precision' in metrics
        assert 'recall' in metrics
        assert 'f1' in metrics
        assert 'feature_importances' in metrics
        assert 'confusion_matrix' in metrics

    def test_metrics_values_in_range(self):
        from fraud_detector import FraudDetector
        fd = FraudDetector()
        metrics = fd.get_ml_metrics()
        assert 0.0 <= metrics['accuracy'] <= 1.0
        assert 0.0 <= metrics['precision'] <= 1.0
        assert 0.0 <= metrics['recall'] <= 1.0
        assert 0.0 <= metrics['f1'] <= 1.0

    def test_feature_importances_sum_to_one(self):
        from fraud_detector import FraudDetector
        fd = FraudDetector()
        metrics = fd.get_ml_metrics()
        total = sum(f['importance'] for f in metrics['feature_importances'])
        assert abs(total - 1.0) < 0.01, f"Sum={total}"

    def test_feature_importances_count(self):
        from fraud_detector import FraudDetector
        fd = FraudDetector()
        metrics = fd.get_ml_metrics()
        assert len(metrics['feature_importances']) == 7
