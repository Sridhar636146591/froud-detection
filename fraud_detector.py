import numpy as np
from sklearn.ensemble import IsolationForest
import database as db
import re
from datetime import datetime, timedelta
from ai_simulator import ai_simulator
from network_analyzer import network_analyzer

class AdvancedFraudDetector:
    """Advanced fraud detection with 20+ features"""
    
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100
        )
        self.is_trained = False
        self.income_threshold = 300000
        
        # Scheme-specific income limits
        self.scheme_income_limits = {
            'PM-KISAN': 200000,
            'MGNREGA': 0,
            'Ayushman Bharat': 500000,
            'PM Awas Yojana': 300000,
            'Old Age Pension': 200000,
            'Widow Pension': 200000,
            'Disability Pension': 200000,
            'Other': 300000
        }
        
        # Geographic restrictions
        self.geo_restrictions = {
            'PM-KISAN': ['rural'],
            'MGNREGA': ['rural', 'semi-urban'],
            'PM Awas Yojana': ['rural', 'urban']
        }
    
    # ===== FEATURE 1: Predictive Fraud Detection =====
    def predict_future_risk(self, application_data):
        """Use AI to predict future fraud risk"""
        prediction = ai_simulator.predict_fraud_risk(application_data)
        return {
            'feature': 'Predictive Fraud Detection',
            'enabled': True,
            'prediction': prediction,
            'risk_added': 10 if prediction['predicted_score'] > 70 else 5 if prediction['predicted_score'] > 50 else 0
        }
    
    # ===== FEATURE 2: Network Analysis =====
    def analyze_network_connections(self, application_data):
        """Detect fraud rings through network analysis"""
        network_analysis = network_analyzer.analyze_application_network(application_data)
        return {
            'feature': 'Network/Graph Analysis',
            'enabled': True,
            'analysis': network_analysis,
            'risk_added': network_analysis['network_risk_score'] // 3,
            'is_fraud_ring': network_analysis['is_part_of_ring']
        }
    
    # ===== FEATURE 3: Document Forgery Detection =====
    def detect_document_forgery(self, document_data):
        """Simulate document forgery detection"""
        doc_analysis = ai_simulator.analyze_document(document_data)
        return {
            'feature': 'Document Forgery Detection',
            'enabled': True,
            'analysis': doc_analysis,
            'risk_added': int(doc_analysis['forgery_score'] // 2),
            'is_suspicious': not doc_analysis['is_authentic']
        }
    
    # ===== FEATURE 4: Deepfake/Face Spoof Detection =====
    def detect_face_spoof(self, image_data):
        """Simulate deepfake and face spoof detection"""
        face_analysis = ai_simulator.detect_deepfake(image_data)
        return {
            'feature': 'Deepfake/Face Spoof Detection',
            'enabled': True,
            'analysis': face_analysis,
            'risk_added': 50 if face_analysis['spoof_detected'] else int(face_analysis['deepfake_probability'] // 3),
            'is_spoof': face_analysis['spoof_detected']
        }
    
    # ===== FEATURE 5: Time-Based Anomaly Detection =====
    def detect_time_anomaly(self, submission_time=None):
        """Detect unusual submission times and patterns"""
        if submission_time is None:
            submission_time = datetime.now()
        
        hour = submission_time.hour
        reasons = []
        risk = 0
        
        # Late night submissions (11 PM - 5 AM)
        if hour >= 23 or hour < 5:
            risk += 20
            reasons.append(f"Suspicious late-night submission at {hour}:00")
        
        # Early morning (5 AM - 6 AM)
        elif hour < 6:
            risk += 10
            reasons.append(f"Unusual early morning submission at {hour}:00")
        
        # Check rapid submissions from same IP (simulated)
        conn = db.get_db_connection()
        recent_count = conn.execute('''
            SELECT COUNT(*) FROM applications 
            WHERE created_at >= datetime('now', '-1 hour')
        ''').fetchone()[0]
        conn.close()
        
        if recent_count > 10:
            risk += 25
            reasons.append(f"High volume of submissions in last hour ({recent_count})")
        
        return {
            'feature': 'Time-Based Anomaly Detection',
            'enabled': True,
            'submission_hour': hour,
            'risk_added': risk,
            'reasons': reasons,
            'is_suspicious': risk > 15
        }
    
    # ===== FEATURE 6: Geo-Fencing & Location Intelligence =====
    def check_geo_fencing(self, application_data, ip_address=None):
        """Check geographic eligibility and anomalies"""
        scheme = application_data.get('scheme', '')
        district = application_data.get('district', '')
        reasons = []
        risk = 0
        
        # Simulate IP geolocation
        geo_data = {
            'city': district or 'Unknown',
            'region': 'Local',
            'country': 'India',
            'is_eligible_region': True
        }
        
        # Check scheme-specific geographic restrictions
        if scheme in self.geo_restrictions:
            # Simulate region check
            if district and 'urban' in district.lower() and scheme == 'PM-KISAN':
                risk += 30
                reasons.append(f"Urban applicant for rural scheme: {scheme}")
                geo_data['is_eligible_region'] = False
        
        # Check for foreign IP (simulated)
        if ip_address and not ip_address.startswith(('10.', '172.', '192.')):
            if 'foreign' in ip_address.lower():
                risk += 40
                reasons.append("Application from outside India detected")
        
        return {
            'feature': 'Geo-Fencing & Location Intelligence',
            'enabled': True,
            'geo_data': geo_data,
            'risk_added': risk,
            'reasons': reasons,
            'is_valid_location': risk < 30
        }
    
    # ===== FEATURE 7: Financial Pattern Monitoring =====
    def analyze_financial_patterns(self, application_data):
        """Monitor bank account reuse and suspicious patterns"""
        bank_account = application_data.get('bank_account', '')
        reasons = []
        risk = 0
        
        conn = db.get_db_connection()
        
        # Check bank account reuse
        if bank_account:
            reuse_count = conn.execute('''
                SELECT COUNT(*) FROM financial_transactions 
                WHERE bank_account = ?
            ''', (bank_account,)).fetchone()[0]
            
            if reuse_count > 2:
                risk += 25
                reasons.append(f"Bank account used in {reuse_count} applications")
        
        # Check income vs scheme eligibility
        scheme = application_data.get('scheme', '')
        income = application_data.get('income', 0)
        limit = self.scheme_income_limits.get(scheme, 300000)
        
        if limit > 0 and income > limit:
            risk += 20
            reasons.append(f"Income {income} exceeds scheme limit {limit}")
        
        conn.close()
        
        return {
            'feature': 'Financial Pattern Monitoring',
            'enabled': True,
            'risk_added': risk,
            'reasons': reasons,
            'is_suspicious': risk > 15
        }
    
    # ===== FEATURE 8: Reverse Verification System =====
    def check_reverse_verification(self, application_data):
        """Check external verification status"""
        conn = db.get_db_connection()
        
        # Check for pending verifications
        pending = conn.execute('''
            SELECT COUNT(*) FROM verification_requests 
            WHERE verification_status = 'pending'
        ''').fetchone()[0]
        
        # Simulate verification results
        verification_status = {
            'employer_verified': random.choice([True, True, True, False]),  # 75% pass
            'bank_verified': random.choice([True, True, True, False]),
            'address_verified': random.choice([True, True, False])
        }
        
        failed_count = sum(1 for v in verification_status.values() if not v)
        
        conn.close()
        
        return {
            'feature': 'Reverse Verification System',
            'enabled': True,
            'verification_status': verification_status,
            'pending_count': pending,
            'risk_added': failed_count * 15,
            'requires_verification': failed_count > 0
        }
    
    # ===== FEATURE 9: Social Trust Scoring =====
    def calculate_trust_score(self, aadhaar, phone):
        """Calculate social trust score based on history"""
        conn = db.get_db_connection()
        
        # Get existing trust score or create new
        trust = conn.execute('''
            SELECT * FROM trust_scores WHERE aadhaar = ?
        ''', (aadhaar,)).fetchone()
        
        if not trust:
            # Calculate initial trust score
            base_score = 50
            
            # Check application history
            app_count = conn.execute('''
                SELECT COUNT(*) FROM applications WHERE aadhaar = ?
            ''', (aadhaar,)).fetchone()[0]
            
            # More applications = slightly higher trust (established user)
            history_factor = min(20, app_count * 5)
            
            # Check for rejections
            rejections = conn.execute('''
                SELECT COUNT(*) FROM applications 
                WHERE aadhaar = ? AND classification = 'REJECT'
            ''', (aadhaar,)).fetchone()[0]
            
            consistency_factor = -15 if rejections > 0 else 10
            
            trust_score = base_score + history_factor + consistency_factor
            trust_score = max(0, min(100, trust_score))
            
            # Insert new trust score
            conn.execute('''
                INSERT INTO trust_scores (aadhaar, phone, trust_score, history_factor, consistency_factor)
                VALUES (?, ?, ?, ?, ?)
            ''', (aadhaar, phone, trust_score, history_factor, consistency_factor))
            conn.commit()
        else:
            trust_score = trust['trust_score']
        
        conn.close()
        
        return {
            'feature': 'Social Trust Scoring',
            'enabled': True,
            'trust_score': trust_score,
            'trust_level': 'High' if trust_score > 70 else 'Medium' if trust_score > 40 else 'Low',
            'risk_reduction': trust_score // 10,  # Higher trust = lower risk
            'verification_badge': trust_score > 75
        }
    
    # ===== FEATURE 10: Bot Detection =====
    def detect_bot(self, behavior_data):
        """Detect automated/bot submissions"""
        bot_analysis = ai_simulator.detect_bot_behavior(behavior_data)
        return {
            'feature': 'Bot Detection System',
            'enabled': True,
            'analysis': bot_analysis,
            'risk_added': int(bot_analysis['bot_probability']),
            'is_bot': bot_analysis['is_likely_bot']
        }
    
    # ===== FEATURE 12: Explainable AI =====
    def generate_explanation(self, all_checks, final_score):
        """Generate human-readable explanation for decisions"""
        explanations = []
        
        for check in all_checks:
            if check.get('risk_added', 0) > 0:
                feature_name = check.get('feature', 'Unknown')
                risk = check.get('risk_added', 0)
                
                if 'reasons' in check and check['reasons']:
                    for reason in check['reasons']:
                        explanations.append(f"{feature_name}: {reason} (+{risk} risk)")
                elif 'analysis' in check:
                    analysis = check['analysis']
                    if isinstance(analysis, dict):
                        if 'prediction_factors' in analysis:
                            for factor in analysis['prediction_factors']:
                                explanations.append(f"{feature_name}: {factor}")
                        elif 'indicators' in analysis:
                            for indicator in analysis['indicators']:
                                explanations.append(f"{feature_name}: {indicator}")
        
        return {
            'feature': 'Explainable AI',
            'enabled': True,
            'explanations': explanations,
            'total_factors': len(explanations),
            'summary': f"Application flagged due to {len(explanations)} risk factors" if explanations else "No significant risk factors detected"
        }
    
    # ===== FEATURE 14: Adaptive Security =====
    def get_security_level(self, base_risk, trust_score):
        """Determine adaptive security level"""
        adjusted_risk = base_risk - (trust_score // 10)
        
        if adjusted_risk > 70:
            return {
                'level': 'Maximum',
                'requires_document': True,
                'requires_face': True,
                'requires_verification': True,
                'manual_review': True
            }
        elif adjusted_risk > 50:
            return {
                'level': 'Enhanced',
                'requires_document': True,
                'requires_face': True,
                'requires_verification': False,
                'manual_review': False
            }
        elif adjusted_risk > 30:
            return {
                'level': 'Standard',
                'requires_document': False,
                'requires_face': False,
                'requires_verification': False,
                'manual_review': False
            }
        else:
            return {
                'level': 'Minimal',
                'requires_document': False,
                'requires_face': False,
                'requires_verification': False,
                'manual_review': False
            }
    
    # ===== FEATURE 17: NLP Text Analysis =====
    def analyze_text_nlp(self, text, field_name='description'):
        """Analyze text for suspicious patterns"""
        nlp_analysis = ai_simulator.analyze_text_nlp(text, field_name)
        return {
            'feature': 'NLP-Based Text Analysis',
            'enabled': True,
            'analysis': nlp_analysis,
            'risk_added': nlp_analysis['spam_score'] // 3,
            'is_suspicious': nlp_analysis['spam_score'] > 30 or len(nlp_analysis['risk_flags']) > 0
        }
    
    # ===== FEATURE 18: Benefit Abuse Tracking =====
    def check_benefit_abuse(self, aadhaar, current_scheme):
        """Track and detect benefit abuse across schemes"""
        conn = db.get_db_connection()
        
        # Get all benefits for this Aadhaar
        benefits = conn.execute('''
            SELECT scheme, COUNT(*) as claim_count, SUM(benefit_amount) as total_amount
            FROM benefit_tracking
            WHERE aadhaar = ?
            GROUP BY scheme
        ''', (aadhaar,)).fetchall()
        
        schemes_claimed = [b['scheme'] for b in benefits]
        total_claims = sum(b['claim_count'] for b in benefits)
        
        # Check for simultaneous claims
        current_claims = conn.execute('''
            SELECT COUNT(*) FROM applications 
            WHERE aadhaar = ? AND classification IN ('APPROVE', 'REVIEW')
        ''', (aadhaar,)).fetchone()[0]
        
        conn.close()
        
        risk = 0
        reasons = []
        
        if total_claims > 3:
            risk += 20
            reasons.append(f"Multiple scheme claims: {total_claims}")
        
        if current_scheme in schemes_claimed:
            risk += 30
            reasons.append(f"Duplicate claim for {current_scheme}")
        
        return {
            'feature': 'Benefit Abuse Tracking',
            'enabled': True,
            'schemes_claimed': schemes_claimed,
            'total_claims': total_claims,
            'current_active': current_claims,
            'risk_added': risk,
            'reasons': reasons,
            'is_abuse': risk > 20
        }
    
    # ===== FEATURE 20: Blacklist/Whitelist Check =====
    def check_lists(self, aadhaar, phone, bank_account=''):
        """Check against blacklist and whitelist"""
        conn = db.get_db_connection()
        
        entities_to_check = [
            ('aadhaar', aadhaar),
            ('phone', phone),
            ('bank_account', bank_account)
        ]
        
        results = {'blacklisted': [], 'whitelisted': []}
        
        for entity_type, entity_value in entities_to_check:
            if not entity_value:
                continue
                
            list_entry = conn.execute('''
                SELECT * FROM blacklist_whitelist 
                WHERE entity_type = ? AND entity_value = ?
            ''', (entity_type, entity_value)).fetchone()
            
            if list_entry:
                entry_dict = {
                    'entity_type': entity_type,
                    'entity_value': entity_value[:4] + '****',
                    'reason': list_entry['reason'],
                    'auto_added': list_entry['auto_added']
                }
                
                if list_entry['list_type'] == 'blacklist':
                    results['blacklisted'].append(entry_dict)
                else:
                    results['whitelisted'].append(entry_dict)
        
        conn.close()
        
        is_blacklisted = len(results['blacklisted']) > 0
        is_whitelisted = len(results['whitelisted']) > 0 and not is_blacklisted
        
        return {
            'feature': 'Automatic Blacklisting & Whitelisting',
            'enabled': True,
            'blacklisted': results['blacklisted'],
            'whitelisted': results['whitelisted'],
            'is_blacklisted': is_blacklisted,
            'is_whitelisted': is_whitelisted,
            'risk_added': 100 if is_blacklisted else -20 if is_whitelisted else 0,
            'action': 'REJECT' if is_blacklisted else 'FAST_TRACK' if is_whitelisted else 'NORMAL'
        }


# Keep original FraudDetector for backward compatibility
class FraudDetector(AdvancedFraudDetector):
    """Backward-compatible fraud detector"""
    pass

# Global detector instance
fraud_detector = AdvancedFraudDetector()
import random

class FraudDetector:
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100
        )
        self.is_trained = False
        self.income_threshold = 300000  # Income limit for eligibility
        
        # Scheme-specific income limits
        self.scheme_income_limits = {
            'PM-KISAN': 200000,
            'MGNREGA': 0,  # No income limit
            'Ayushman Bharat': 500000,
            'PM Awas Yojana': 300000,
            'Old Age Pension': 200000,
            'Widow Pension': 200000,
            'Disability Pension': 200000,
            'Other': 300000
        }
        
    def train_model(self, X):
        """Train the Isolation Forest model on synthetic/historical data"""
        if len(X) > 0:
            self.model.fit(X)
            self.is_trained = True
    
    def calculate_rule_score(self, name, aadhaar, phone, income, address, scheme=None, age=None, gender=None, district=None):
        """Calculate rule-based fraud score with enhanced checks"""
        score = 0
        reasons = []
        
        # Check 1: Duplicate Aadhaar (+40 points)
        duplicate_count = db.check_duplicate_aadhaar(aadhaar)
        if duplicate_count > 0:
            score += 40
            reasons.append(f"Duplicate Aadhaar detected ({duplicate_count} existing application(s))")
        
        # Check 2: Same phone, different name (+30 points)
        if db.check_phone_name_mismatch(phone, name):
            score += 30
            reasons.append("Same phone number used with different name")
        
        # Check 3: Multiple applications from same phone (+20 points)
        phone_count = db.get_applications_by_phone(phone)
        if phone_count > 0:
            score += 20
            reasons.append(f"Multiple applications from same phone ({phone_count + 1} total)")
        
        # Check 4: Income exceeds eligibility limit (+20 points)
        if income > self.income_threshold:
            score += 20
            reasons.append(f"Income (₹{income:,.0f}) exceeds eligibility limit (₹{self.income_threshold:,.0f})")
        
        # Check 5: Similar address detected (+10 points)
        similar_count = db.get_similar_addresses(address)
        if similar_count > 0:
            score += 10
            reasons.append(f"Similar address pattern detected ({similar_count} similar address(es))")
        
        # Check 6: Scheme-specific income validation (+25 points)
        if scheme and scheme in self.scheme_income_limits:
            scheme_limit = self.scheme_income_limits[scheme]
            if scheme_limit > 0 and income > scheme_limit:
                score += 25
                reasons.append(f"Income exceeds {scheme} scheme limit (₹{scheme_limit:,.0f})")
        
        # Check 7: Invalid Aadhaar format (+35 points)
        if not self._validate_aadhaar(aadhaar):
            score += 35
            reasons.append("Invalid Aadhaar number format")
        
        # Check 8: Invalid phone format (+15 points)
        if not self._validate_phone(phone):
            score += 15
            reasons.append("Invalid phone number format")
        
        # Check 9: Suspicious name patterns (+20 points)
        name_check = self._check_suspicious_name(name)
        if name_check:
            score += 20
            reasons.append(name_check)
        
        # Check 10: Address quality check (+10 points)
        address_check = self._check_address_quality(address)
        if address_check:
            score += 10
            reasons.append(address_check)
        
        # Check 11: Age-based validation (+15 points)
        if age is not None:
            age_check = self._validate_age(age, scheme)
            if age_check:
                score += 15
                reasons.append(age_check)
        
        # Check 12: High-value application clustering (+20 points)
        cluster_check = self._check_application_clustering(phone, address)
        if cluster_check:
            score += 20
            reasons.append(cluster_check)
        
        # Check 13: Rapid application pattern (+25 points)
        rapid_check = self._check_rapid_applications(phone)
        if rapid_check:
            score += 25
            reasons.append(rapid_check)
        
        return score, reasons
    
    def _validate_aadhaar(self, aadhaar):
        """Validate Aadhaar number format"""
        if not aadhaar or len(aadhaar) != 12:
            return False
        if not aadhaar.isdigit():
            return False
        # Check for repeated digits (potential fake)
        if len(set(aadhaar)) < 4:
            return False
        return True
    
    def _validate_phone(self, phone):
        """Validate phone number format"""
        if not phone or len(phone) != 10:
            return False
        if not phone.isdigit():
            return False
        # Check for repeated digits
        if len(set(phone)) < 5:
            return False
        # Check for sequential digits
        if phone in ['0123456789', '9876543210', '1111111111', '0000000000']:
            return False
        return True
    
    def _check_suspicious_name(self, name):
        """Check for suspicious name patterns"""
        if not name:
            return "Name field is empty"
        
        # Check for all caps
        if name.isupper():
            return "Name in all capital letters (suspicious)"
        
        # Check for all lowercase
        if name.islower():
            return "Name in all lowercase letters (suspicious)"
        
        # Check for numbers in name
        if any(char.isdigit() for char in name):
            return "Name contains numbers (suspicious)"
        
        # Check for special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', name):
            return "Name contains special characters (suspicious)"
        
        # Check for single character names
        if len(name.strip()) < 3:
            return "Name too short (suspicious)"
        
        # Check for repeated characters
        if any(name.count(char) > 5 for char in set(name.lower())):
            return "Name has unusual character repetition"
        
        return None
    
    def _check_address_quality(self, address):
        """Check address quality indicators"""
        if not address:
            return "Address is empty"
        
        # Check minimum length
        if len(address) < 10:
            return "Address too short (incomplete)"
        
        # Check for numbers (should have house number or pincode)
        if not any(char.isdigit() for char in address):
            return "Address lacks numeric information (no house number/pincode)"
        
        # Check for common address words
        common_words = ['road', 'street', 'lane', 'nagar', 'colony', 'village', 'district', 'near', 'opposite']
        if not any(word in address.lower() for word in common_words):
            return "Address lacks standard location descriptors"
        
        return None
    
    def _validate_age(self, age, scheme):
        """Validate age against scheme requirements"""
        if age < 18:
            return f"Applicant age ({age}) below minimum (18 years)"
        
        if age > 100:
            return f"Applicant age ({age}) seems unrealistic"
        
        # Scheme-specific age checks
        if scheme == 'Old Age Pension' and age < 60:
            return f"Age ({age}) below Old Age Pension requirement (60+)"
        
        if scheme == 'Widow Pension' and age < 21:
            return f"Age ({age}) below Widow Pension requirement (21+)"
        
        return None
    
    def _check_application_clustering(self, phone, address):
        """Check for suspicious application clustering"""
        # Check if same phone has been used with multiple addresses
        phone_apps = db.get_applications_count_by_phone(phone)
        if phone_apps >= 3:
            return f"High application volume from same phone ({phone_apps} applications)"
        
        return None
    
    def _check_rapid_applications(self, phone):
        """Check for rapid-fire applications from same phone"""
        recent_count = db.get_recent_applications_by_phone(phone, hours=24)
        if recent_count >= 2:
            return f"Multiple applications within 24 hours ({recent_count} applications)"
        
        return None
    
    def calculate_ml_score(self, features):
        """Calculate ML-based anomaly score using Isolation Forest"""
        if not self.is_trained:
            # Train with synthetic data if not trained
            synthetic_data = self._generate_synthetic_training_data()
            self.train_model(synthetic_data)
        
        features_array = np.array(features).reshape(1, -1)
        anomaly_score = self.model.decision_function(features_array)[0]
        # Convert to 0-30 scale (higher score = more anomalous)
        ml_score = int((1 - (anomaly_score + 0.5)) * 30)
        ml_score = max(0, min(30, ml_score))  # Clamp between 0-30
        return ml_score
    
    def _generate_synthetic_training_data(self):
        """Generate synthetic training data for initial model training"""
        np.random.seed(42)
        n_samples = 1000
        
        # Generate normal applications
        normal_income = np.random.normal(150000, 50000, int(n_samples * 0.95))
        normal_duplicates = np.random.poisson(0.1, int(n_samples * 0.95))
        normal_address_sim = np.random.beta(2, 5, int(n_samples * 0.95))
        normal_freq = np.random.poisson(0.5, int(n_samples * 0.95))
        normal_name_quality = np.random.binomial(1, 0.05, int(n_samples * 0.95))
        normal_address_quality = np.random.binomial(1, 0.05, int(n_samples * 0.95))
        normal_age_risk = np.random.binomial(1, 0.02, int(n_samples * 0.95))
        
        # Generate fraudulent applications (outliers)
        fraud_income = np.random.normal(500000, 100000, int(n_samples * 0.05))
        fraud_duplicates = np.random.poisson(3, int(n_samples * 0.05))
        fraud_address_sim = np.random.beta(5, 2, int(n_samples * 0.05))
        fraud_freq = np.random.poisson(5, int(n_samples * 0.05))
        fraud_name_quality = np.random.binomial(1, 0.4, int(n_samples * 0.05))
        fraud_address_quality = np.random.binomial(1, 0.3, int(n_samples * 0.05))
        fraud_age_risk = np.random.binomial(1, 0.2, int(n_samples * 0.05))
        
        X = np.column_stack([
            np.concatenate([normal_income, fraud_income]),
            np.concatenate([normal_duplicates, fraud_duplicates]),
            np.concatenate([normal_address_sim, fraud_address_sim]),
            np.concatenate([normal_freq, fraud_freq]),
            np.concatenate([normal_name_quality, fraud_name_quality]),
            np.concatenate([normal_address_quality, fraud_address_quality]),
            np.concatenate([normal_age_risk, fraud_age_risk])
        ])
        
        return X
    
    def detect_fraud(self, name, aadhaar, phone, income, address, scheme=None, age=None, gender=None, district=None):
        """Main fraud detection method combining rules and ML with enhanced checks"""
        # Calculate rule-based score with all parameters
        rule_score, reasons = self.calculate_rule_score(name, aadhaar, phone, income, address, scheme, age, gender, district)
        
        # Prepare features for ML model
        duplicate_count = db.check_duplicate_aadhaar(aadhaar)
        phone_count = db.get_applications_by_phone(phone)
        address_similarity = min(1.0, db.get_similar_addresses(address) / 5.0)  # Normalize
        
        # Additional ML features
        name_quality = 1 if self._check_suspicious_name(name) else 0
        address_quality = 1 if self._check_address_quality(address) else 0
        age_risk = 1 if (age and (age < 18 or age > 100)) else 0
        
        features = [
            income,
            duplicate_count,
            address_similarity,
            phone_count,
            name_quality,
            address_quality,
            age_risk
        ]
        
        # Calculate ML score
        ml_score = self.calculate_ml_score(features)
        
        # Combine scores (70% rules, 30% ML)
        final_score = int(rule_score * 0.7 + ml_score)
        final_score = min(100, final_score)  # Cap at 100
        
        # Add ML reason if significant
        if ml_score > 15:
            reasons.append(f"ML anomaly detection flagged unusual patterns (score: {ml_score})")
        
        # Classification with risk levels
        if final_score >= 70:
            classification = "REJECT"
            risk_level = "HIGH"
        elif final_score >= 40:
            classification = "REVIEW"
            risk_level = "MEDIUM"
        else:
            classification = "APPROVE"
            risk_level = "LOW"
        
        return {
            'risk_score': final_score,
            'classification': classification,
            'risk_level': risk_level,
            'reasons': reasons if reasons else ["No fraud indicators detected"],
            'rule_score': rule_score,
            'ml_score': ml_score,
            'checks_performed': 13,
            'scheme_checked': scheme if scheme else "Not specified"
        }

# Global fraud detector instance
fraud_detector = FraudDetector()
