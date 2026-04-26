"""
AI/ML Simulation Module for Fraud Detection
Provides simulated AI services for demonstration purposes
"""

import random
import hashlib
import json
from datetime import datetime

class AISimulator:
    """Simulates AI/ML services for fraud detection"""
    
    @staticmethod
    def predict_fraud_risk(application_data):
        """
        Simulate ML model predicting future fraud risk
        Returns: dict with predicted risk score, confidence, and factors
        """
        # Simulate based on application patterns
        base_score = application_data.get('risk_score', 50)
        
        # Add some ML "intelligence" simulation
        factors = []
        confidence = random.uniform(0.75, 0.95)
        
        # Historical pattern simulation
        if application_data.get('past_applications', 0) > 3:
            factors.append("Multiple past applications detected")
            base_score += 10
        
        if application_data.get('income', 0) > 1000000:
            factors.append("High income bracket - premium target")
            base_score += 5
            
        # Time-based patterns
        hour = datetime.now().hour
        if hour < 6 or hour > 23:
            factors.append("Unusual submission time")
            base_score += 15
            
        # Device/location patterns
        if application_data.get('new_device', False):
            factors.append("New device detected")
            base_score += 8
            
        # Simulate prediction trend
        trend = random.choice(['increasing', 'stable', 'decreasing'])
        if trend == 'increasing':
            predicted_score = min(100, base_score + random.randint(5, 15))
            factors.append("Risk trend: Increasing")
        elif trend == 'decreasing':
            predicted_score = max(0, base_score - random.randint(5, 10))
            factors.append("Risk trend: Decreasing")
        else:
            predicted_score = base_score
            factors.append("Risk trend: Stable")
        
        return {
            'current_score': base_score,
            'predicted_score': predicted_score,
            'confidence': round(confidence, 2),
            'prediction_factors': factors,
            'risk_level': 'High' if predicted_score > 70 else 'Medium' if predicted_score > 40 else 'Low',
            'recommended_action': 'Enhanced Verification' if predicted_score > 60 else 'Standard Process'
        }
    
    @staticmethod
    def analyze_document(document_data):
        """
        Simulate OCR and document forgery detection
        Returns: dict with verification results
        """
        # Simulate document analysis
        doc_type = document_data.get('type', 'unknown')
        
        # Simulate OCR confidence
        ocr_confidence = random.uniform(0.85, 0.99)
        
        # Simulate forgery detection (higher score = more suspicious)
        forgery_indicators = []
        forgery_score = random.uniform(0, 30)
        
        # Randomly add some forgery indicators for demo
        if random.random() < 0.1:  # 10% chance of suspicious document
            forgery_score = random.uniform(60, 95)
            forgery_indicators = [
                "Inconsistent font detected",
                "Digital manipulation artifacts found",
                "Metadata inconsistency"
            ]
        
        # Extract simulated data
        extracted_data = {
            'name': document_data.get('expected_name', 'Unknown'),
            'document_number': f"DOC{random.randint(100000, 999999)}",
            'issue_date': datetime.now().strftime('%Y-%m-%d'),
            'expiry_date': '2030-12-31'
        }
        
        return {
            'document_type': doc_type,
            'ocr_confidence': round(ocr_confidence, 2),
            'forgery_score': round(forgery_score, 2),
            'forgery_indicators': forgery_indicators,
            'is_authentic': forgery_score < 50,
            'verification_status': 'Verified' if forgery_score < 50 else 'Suspicious',
            'extracted_data': extracted_data,
            'recommendation': 'Accept' if forgery_score < 50 else 'Manual Review'
        }
    
    @staticmethod
    def detect_deepfake(image_data):
        """
        Simulate deepfake and face spoof detection
        Returns: dict with liveness and authenticity results
        """
        # Simulate liveness detection
        liveness_score = random.uniform(0.90, 0.99)
        
        # Simulate deepfake probability
        deepfake_prob = random.uniform(0, 15)
        
        # Randomly flag some as suspicious
        spoof_detected = False
        spoof_indicators = []
        
        if random.random() < 0.05:  # 5% chance of spoof
            spoof_detected = True
            liveness_score = random.uniform(0.30, 0.60)
            deepfake_prob = random.uniform(70, 95)
            spoof_indicators = [
                "Screen replay attack detected",
                "2D mask suspected",
                "Inconsistent lighting patterns"
            ]
        
        return {
            'liveness_score': round(liveness_score, 2),
            'deepfake_probability': round(deepfake_prob, 2),
            'spoof_detected': spoof_detected,
            'spoof_indicators': spoof_indicators,
            'is_real_person': not spoof_detected and deepfake_prob < 50,
            'verification_status': 'Verified' if not spoof_detected else 'Spoof Detected',
            'confidence': round(liveness_score, 2)
        }
    
    @staticmethod
    def analyze_text_nlp(text, field_name='description'):
        """
        Simulate NLP analysis for fraud patterns
        Returns: dict with text analysis results
        """
        if not text:
            return {
                'spam_score': 0,
                'similarity_score': 0,
                'patterns_detected': [],
                'sentiment': 'neutral',
                'risk_flags': []
            }
        
        # Simulate spam detection
        spam_indicators = ['urgent', 'winner', 'lottery', 'free', 'click here', 'limited']
        spam_score = sum(1 for indicator in spam_indicators if indicator.lower() in text.lower()) * 10
        
        # Simulate pattern detection
        patterns = []
        risk_flags = []
        
        # Check for copy-paste patterns (repeated phrases)
        words = text.lower().split()
        if len(words) > 20:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.4:
                patterns.append("High repetition detected - possible template")
                risk_flags.append("Template usage suspected")
        
        # Check for suspicious phrases
        suspicious_phrases = ['fake', 'temporary', 'dont check', 'ignore', 'wrong address']
        for phrase in suspicious_phrases:
            if phrase in text.lower():
                patterns.append(f"Suspicious phrase: '{phrase}'")
                risk_flags.append("Suspicious language detected")
        
        # Simulate similarity to known fraud (0-100)
        similarity_score = random.uniform(5, 25)
        if 'guarantee' in text.lower() or 'promise' in text.lower():
            similarity_score += 20
            patterns.append("Guarantee language detected")
        
        return {
            'spam_score': min(100, spam_score),
            'similarity_score': round(similarity_score, 2),
            'patterns_detected': patterns,
            'sentiment': random.choice(['positive', 'neutral', 'negative']),
            'risk_flags': risk_flags,
            'word_count': len(words),
            'complexity_score': round(len(set(words)) / max(len(words), 1) * 100, 2)
        }
    
    @staticmethod
    def detect_bot_behavior(behavior_data):
        """
        Simulate bot detection based on behavior patterns
        Returns: dict with bot probability analysis
        """
        bot_score = 0
        indicators = []
        
        # Check typing speed (too fast = bot)
        typing_speed = behavior_data.get('typing_speed', 200)  # chars per minute
        if typing_speed > 800:
            bot_score += 30
            indicators.append("Unusually fast typing")
        elif typing_speed < 50:
            bot_score += 20
            indicators.append("Suspiciously slow typing")
        
        # Check mouse movements
        mouse_moves = behavior_data.get('mouse_movements', 100)
        if mouse_moves < 10:
            bot_score += 25
            indicators.append("Minimal mouse activity")
        
        # Check form interaction time
        time_on_page = behavior_data.get('time_on_page', 60)  # seconds
        if time_on_page < 5:
            bot_score += 35
            indicators.append("Form completed too quickly")
        
        # Check form interactions
        interactions = behavior_data.get('form_interactions', 10)
        if interactions < 3:
            bot_score += 15
            indicators.append("Limited form interaction")
        
        # Add some randomness for realistic simulation
        bot_score += random.randint(-5, 5)
        bot_score = max(0, min(100, bot_score))
        
        return {
            'bot_probability': round(bot_score, 2),
            'is_likely_bot': bot_score > 60,
            'confidence': round(min(100, bot_score + 20), 2) if bot_score > 30 else round(random.uniform(60, 80), 2),
            'indicators': indicators,
            'recommendation': 'Block' if bot_score > 80 else 'Challenge' if bot_score > 50 else 'Allow',
            'behavior_data': behavior_data
        }
    
    @staticmethod
    def generate_fraud_simulation():
        """
        Generate simulated fraud scenarios for testing
        Returns: list of fraud test cases
        """
        scenarios = [
            {
                'name': 'Duplicate Identity Fraud',
                'description': 'Same Aadhaar used with different names',
                'detection_method': 'Aadhaar cross-reference',
                'expected_result': 'Flagged',
                'severity': 'High'
            },
            {
                'name': 'Income Manipulation',
                'description': 'False income certificate submitted',
                'detection_method': 'Document verification + external validation',
                'expected_result': 'Rejected',
                'severity': 'High'
            },
            {
                'name': 'Bot Registration',
                'description': 'Automated mass application submission',
                'detection_method': 'Behavior analysis + rate limiting',
                'expected_result': 'Blocked',
                'severity': 'Medium'
            },
            {
                'name': 'Fraud Ring',
                'description': 'Multiple applications from connected network',
                'detection_method': 'Network graph analysis',
                'expected_result': 'Under Review',
                'severity': 'Critical'
            },
            {
                'name': 'Document Forgery',
                'description': 'Tampered income certificate',
                'detection_method': 'OCR + forgery detection',
                'expected_result': 'Rejected',
                'severity': 'High'
            },
            {
                'name': 'Geographic Fraud',
                'description': 'Application from ineligible region',
                'detection_method': 'Geo-fencing + address verification',
                'expected_result': 'Rejected',
                'severity': 'Medium'
            },
            {
                'name': 'Benefit Stacking',
                'description': 'Same person claiming multiple schemes',
                'detection_method': 'Cross-scheme analysis',
                'expected_result': 'Flagged',
                'severity': 'Medium'
            },
            {
                'name': 'Deepfake Identity',
                'description': 'Synthetic identity using deepfake photo',
                'detection_method': 'Face liveness detection',
                'expected_result': 'Rejected',
                'severity': 'Critical'
            }
        ]
        
        return scenarios


# Global AI simulator instance
ai_simulator = AISimulator()
