"""
Generate dummy data for fraud detection visualization
"""

import database as db
from datetime import datetime, timedelta
import random
from ai_simulator import ai_simulator

# Sample data pools
FIRST_NAMES = ['Rajesh', 'Priya', 'Amit', 'Sunita', 'Vikram', 'Anita', 'Suresh', 'Deepa', 'Ravi', 'Meena',
               'Kumar', 'Lakshmi', 'Sanjay', 'Pooja', 'Arun', 'Kavita', 'Manoj', 'Sneha', 'Nitin', 'Rekha']

LAST_NAMES = ['Kumar', 'Sharma', 'Singh', 'Patel', 'Reddy', 'Nair', 'Desai', 'Iyer', 'Rao', 'Joshi',
              'Gupta', 'Shah', 'Mehta', 'Shinde', 'Pawar', 'Kulkarni', 'Desai', 'Bhat', 'Rao', 'Menon']

DISTRICTS = ['Mumbai', 'Pune', 'Nagpur', 'Thane', 'Nashik', 'Ahmednagar', 'Solapur', 'Kolhapur', 
             'Aurangabad', 'Jalgaon', 'Satara', 'Sangli', 'Nanded', 'Amravati', 'Dhule']

SCHEMES = ['PM-KISAN', 'MGNREGA', 'Ayushman Bharat', 'PM Awas Yojana', 'Old Age Pension', 
           'Widow Pension', 'Disability Pension', 'Other']

FRAUD_REASONS = [
    "Duplicate Aadhaar detected",
    "Same phone number used with different name",
    "Income exceeds scheme limit",
    "Address appears suspicious/fake",
    "Age validation failed",
    "ML anomaly detected in application pattern",
    "Multiple applications in short time period",
    "Bank account reused across applications"
]

def generate_aadhaar():
    """Generate a random 12-digit Aadhaar number"""
    return ''.join([str(random.randint(0, 9)) for _ in range(12)])

def generate_phone():
    """Generate a random 10-digit Indian phone number"""
    prefixes = ['9', '8', '7', '6']
    return random.choice(prefixes) + ''.join([str(random.randint(0, 9)) for _ in range(9)])

def generate_name():
    """Generate a random Indian name"""
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"

def generate_address(district):
    """Generate a random address"""
    localities = ['Shivaji Nagar', 'Gandhi Chowk', 'Main Road', 'Station Area', 'Market Area',
                  'Housing Colony', 'Industrial Area', 'Temple Street', 'Bus Stand Road']
    return f"{random.randint(1, 999)}, {random.choice(localities)}, {district}, Maharashtra"

def generate_dummy_applications(count=50):
    """Generate dummy applications with varied risk profiles"""
    conn = db.get_db_connection()
    
    # Get existing user IDs
    users = conn.execute('SELECT id FROM users').fetchall()
    user_ids = [u['id'] for u in users] or [1]
    
    print(f"Generating {count} dummy applications...")
    
    for i in range(count):
        # Generate basic info
        name = generate_name()
        aadhaar = generate_aadhaar()
        phone = generate_phone()
        district = random.choice(DISTRICTS)
        address = generate_address(district)
        scheme = random.choice(SCHEMES)
        age = random.randint(25, 75)
        gender = random.choice(['Male', 'Female'])
        
        # Income based on scheme
        if scheme == 'PM-KISAN':
            income = random.randint(50000, 180000)
        elif scheme == 'Ayushman Bharat':
            income = random.randint(100000, 450000)
        else:
            income = random.randint(30000, 400000)
        
        # Determine classification based on fraud probability
        fraud_roll = random.random()
        if fraud_roll < 0.15:  # 15% high risk
            classification = 'REJECT'
            risk_score = random.randint(70, 95)
            reasons = json.dumps(random.sample(FRAUD_REASONS, random.randint(1, 3)))
        elif fraud_roll < 0.35:  # 20% medium risk
            classification = 'REVIEW'
            risk_score = random.randint(45, 69)
            reasons = json.dumps(random.sample(FRAUD_REASONS, 1))
        else:  # 65% low risk
            classification = 'APPROVE'
            risk_score = random.randint(10, 44)
            reasons = json.dumps(["Application appears legitimate"])
        
        # Random date within last 30 days
        days_ago = random.randint(0, 30)
        created_at = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23))
        
        # Insert application
        conn.execute('''
            INSERT INTO applications 
            (name, aadhaar, phone, income, address, scheme, risk_score, classification, reasons, 
             age, gender, district, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, aadhaar, phone, income, address, scheme, risk_score, classification, reasons,
              age, gender, district, random.choice(user_ids), created_at))
        
        application_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Add network links for fraud ring simulation
        if random.random() < 0.2:  # 20% chance of shared entities
            conn.execute('''
                INSERT INTO network_links (entity_type, entity_value, application_id, link_strength)
                VALUES (?, ?, ?, ?)
            ''', ('phone', phone, application_id, random.randint(1, 3)))
        
        if random.random() < 0.1:  # 10% chance of shared Aadhaar (fraud)
            conn.execute('''
                INSERT INTO network_links (entity_type, entity_value, application_id, link_strength)
                VALUES (?, ?, ?, ?)
            ''', ('aadhaar', aadhaar, application_id, random.randint(2, 5)))
        
        # Add geo location data
        conn.execute('''
            INSERT INTO geo_locations 
            (application_id, ip_address, city, region, country, geo_fenced, distance_from_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (application_id, f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
              district, 'Maharashtra', 'India', 1, random.uniform(0, 50)))
        
        # Add trust score
        trust_score = random.randint(30, 95)
        conn.execute('''
            INSERT OR REPLACE INTO trust_scores 
            (aadhaar, phone, trust_score, history_factor, consistency_factor, community_factor)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (aadhaar, phone, trust_score, random.randint(0, 20), 
              random.randint(-10, 15), random.randint(0, 10)))
        
        # Add benefit tracking for some
        if random.random() < 0.3:
            conn.execute('''
                INSERT INTO benefit_tracking 
                (aadhaar, scheme, application_id, benefit_amount, benefit_date, abuse_flag)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (aadhaar, scheme, application_id, random.randint(1000, 50000),
                  created_at, 1 if random.random() < 0.2 else 0))
        
        # Add audit log entry
        conn.execute('''
            INSERT INTO audit_logs 
            (action_type, entity_type, entity_id, user_id, old_values, new_values, 
             ip_address, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('CREATE', 'application', application_id, random.choice(user_ids),
              None, f'Created application for {name}', '127.0.0.1',
              '0' * 64, hash(f'{application_id}{datetime.now()}')))
        
        if (i + 1) % 10 == 0:
            print(f"  Created {i + 1} applications...")
    
    conn.commit()
    conn.close()
    print(f"✓ Successfully created {count} dummy applications!")

def generate_citizen_reports(count=10):
    """Generate citizen fraud reports"""
    conn = db.get_db_connection()
    
    print(f"Generating {count} citizen reports...")
    
    fraud_types = ['identity_theft', 'fake_documents', 'multiple_claims', 'income_falsification', 'address_fraud']
    
    for i in range(count):
        conn.execute('''
            INSERT INTO citizen_reports 
            (reporter_name, reporter_contact, reported_aadhaar, fraud_type, description, report_status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (generate_name(), generate_phone(), generate_aadhaar(),
              random.choice(fraud_types), 
              'Suspicious activity detected in welfare application.',
              random.choice(['pending', 'pending', 'resolved'])))
    
    conn.commit()
    conn.close()
    print(f"✓ Created {count} citizen reports!")

def generate_api_logs(count=100):
    """Generate API access logs"""
    conn = db.get_db_connection()
    
    print(f"Generating {count} API access logs...")
    
    endpoints = ['/api/applications', '/api/stats', '/api/check', '/new-application', '/dashboard']
    
    for i in range(count):
        conn.execute('''
            INSERT INTO api_access_logs 
            (endpoint, method, ip_address, request_count, rate_limit_hit)
            VALUES (?, ?, ?, ?, ?)
        ''', (random.choice(endpoints), random.choice(['GET', 'POST']),
              f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
              random.randint(1, 50), 1 if random.random() < 0.1 else 0))
    
    conn.commit()
    conn.close()
    print(f"✓ Created {count} API access logs!")

def generate_blacklist_entries(count=5):
    """Generate blacklist/whitelist entries"""
    conn = db.get_db_connection()
    
    print("Generating blacklist/whitelist entries...")
    
    # Blacklist entries
    for i in range(count):
        conn.execute('''
            INSERT INTO blacklist_whitelist 
            (entity_type, entity_value, list_type, reason, auto_added)
            VALUES (?, ?, ?, ?, ?)
        ''', (random.choice(['aadhaar', 'phone', 'bank_account']),
              generate_aadhaar() if random.random() < 0.5 else generate_phone(),
              'blacklist', 'Confirmed fraud case', 0))
    
    # Whitelist entries
    for i in range(3):
        conn.execute('''
            INSERT INTO blacklist_whitelist 
            (entity_type, entity_value, list_type, reason, auto_added)
            VALUES (?, ?, ?, ?, ?)
        ''', (random.choice(['aadhaar', 'phone']),
              generate_aadhaar() if random.random() < 0.5 else generate_phone(),
              'whitelist', 'Verified government employee', 0))
    
    conn.commit()
    conn.close()
    print(f"✓ Created blacklist/whitelist entries!")

if __name__ == '__main__':
    import json
    
    print("=" * 60)
    print("FRAUD DETECTION SYSTEM - DUMMY DATA GENERATOR")
    print("=" * 60)
    print()
    
    # Generate all dummy data
    generate_dummy_applications(50)
    print()
    generate_citizen_reports(10)
    print()
    generate_api_logs(100)
    print()
    generate_blacklist_entries(5)
    
    print()
    print("=" * 60)
    print("✓ ALL DUMMY DATA GENERATED SUCCESSFULLY!")
    print("=" * 60)
    print()
    print("You can now view rich visualizations on the dashboard.")
