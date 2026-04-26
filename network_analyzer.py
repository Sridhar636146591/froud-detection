"""
Network Analysis Engine for Fraud Ring Detection
Implements graph-based analysis to detect connected fraudsters
"""

import sqlite3
from collections import defaultdict
from database import get_db_connection, DATABASE

class NetworkAnalyzer:
    """Analyzes connections between applications to detect fraud rings"""
    
    def __init__(self):
        self.db_path = DATABASE
    
    def build_connection_graph(self, application_id=None):
        """
        Build a graph of connections between applications
        Returns: dict with nodes and edges
        """
        conn = get_db_connection()
        
        # Get all network links
        if application_id:
            # Get links for specific application and related ones
            links = conn.execute('''
                SELECT * FROM network_links 
                WHERE application_id = ? 
                OR entity_value IN (
                    SELECT entity_value FROM network_links WHERE application_id = ?
                )
            ''', (application_id, application_id)).fetchall()
        else:
            # Get all links
            links = conn.execute('SELECT * FROM network_links').fetchall()
        
        conn.close()
        
        # Build graph
        graph = {
            'nodes': set(),
            'edges': [],
            'clusters': []
        }
        
        # Group by entity value to find connections
        entity_to_apps = defaultdict(list)
        for link in links:
            entity_to_apps[link['entity_value']].append({
                'application_id': link['application_id'],
                'entity_type': link['entity_type'],
                'link_strength': link['link_strength']
            })
            graph['nodes'].add(link['application_id'])
        
        # Create edges between applications sharing entities
        for entity_value, apps in entity_to_apps.items():
            if len(apps) > 1:
                for i in range(len(apps)):
                    for j in range(i + 1, len(apps)):
                        graph['edges'].append({
                            'source': apps[i]['application_id'],
                            'target': apps[j]['application_id'],
                            'entity_type': apps[i]['entity_type'],
                            'entity_value': entity_value,
                            'strength': apps[i]['link_strength'] + apps[j]['link_strength']
                        })
        
        return graph
    
    def detect_fraud_rings(self, min_ring_size=3):
        """
        Detect clusters of connected applications (fraud rings)
        Returns: list of fraud rings
        """
        graph = self.build_connection_graph()
        
        # Find connected components using Union-Find
        parent = {}
        
        def find(x):
            if x not in parent:
                parent[x] = x
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        
        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py
        
        # Union all connected nodes
        for edge in graph['edges']:
            union(edge['source'], edge['target'])
        
        # Group by component
        components = defaultdict(list)
        for node in graph['nodes']:
            components[find(node)].append(node)
        
        # Filter for rings meeting minimum size
        fraud_rings = []
        for component_id, nodes in components.items():
            if len(nodes) >= min_ring_size:
                ring_info = self._analyze_ring(nodes, graph['edges'])
                fraud_rings.append(ring_info)
        
        return sorted(fraud_rings, key=lambda x: x['risk_score'], reverse=True)
    
    def _analyze_ring(self, application_ids, edges):
        """Analyze a detected fraud ring"""
        conn = get_db_connection()
        
        # Get application details
        apps = []
        for app_id in application_ids:
            app = conn.execute('''
                SELECT a.*, u.full_name as officer_name 
                FROM applications a 
                LEFT JOIN users u ON a.created_by = u.id
                WHERE a.id = ?
            ''', (app_id,)).fetchone()
            if app:
                apps.append(dict(app))
        
        # Get connection types in this ring
        ring_edges = [e for e in edges if e['source'] in application_ids and e['target'] in application_ids]
        connection_types = defaultdict(int)
        for edge in ring_edges:
            connection_types[edge['entity_type']] += 1
        
        # Calculate risk score
        risk_score = min(100, len(application_ids) * 10 + len(ring_edges) * 5)
        
        # Get shared entities
        shared_entities = set()
        for edge in ring_edges:
            shared_entities.add(f"{edge['entity_type']}: {edge['entity_value']}")
        
        conn.close()
        
        return {
            'ring_id': f"RING-{min(application_ids)}",
            'size': len(application_ids),
            'applications': apps,
            'connection_types': dict(connection_types),
            'shared_entities': list(shared_entities)[:5],  # Top 5
            'total_connections': len(ring_edges),
            'risk_score': risk_score,
            'risk_level': 'Critical' if risk_score > 80 else 'High' if risk_score > 60 else 'Medium',
            'detection_confidence': min(100, 50 + len(application_ids) * 5),
            'recommended_action': 'Immediate Investigation' if risk_score > 80 else 'Detailed Review'
        }
    
    def get_network_for_application(self, application_id):
        """Get complete network analysis for a specific application"""
        conn = get_db_connection()
        
        # Get direct connections
        direct_links = conn.execute('''
            SELECT * FROM network_links WHERE application_id = ?
        ''', (application_id,)).fetchall()
        
        # Find related applications through shared entities
        related_apps = []
        for link in direct_links:
            related = conn.execute('''
                SELECT DISTINCT a.*, nl.entity_type, nl.entity_value
                FROM applications a
                JOIN network_links nl ON a.id = nl.application_id
                WHERE nl.entity_value = ? AND a.id != ?
            ''', (link['entity_value'], application_id)).fetchall()
            related_apps.extend([dict(r) for r in related])
        
        # Get application details
        app = conn.execute('''
            SELECT * FROM applications WHERE id = ?
        ''', (application_id,)).fetchone()
        
        conn.close()
        
        # Calculate network metrics
        unique_related = {r['id']: r for r in related_apps}
        
        return {
            'application': dict(app) if app else None,
            'direct_connections': len(direct_links),
            'related_applications': list(unique_related.values()),
            'network_size': len(unique_related) + 1,
            'connection_types': list(set([l['entity_type'] for l in direct_links])),
            'risk_indicators': self._get_network_risk_indicators(direct_links, unique_related)
        }
    
    def _get_network_risk_indicators(self, direct_links, related_apps):
        """Generate risk indicators based on network analysis"""
        indicators = []
        
        if len(related_apps) > 5:
            indicators.append(f"Connected to {len(related_apps)} other applications")
        
        # Check for multiple connection types
        entity_types = [l['entity_type'] for l in direct_links]
        if 'phone' in entity_types and 'ip_address' in entity_types:
            indicators.append("Same phone and IP address across applications")
        
        if 'bank_account' in entity_types:
            indicators.append("Shared bank account detected")
        
        if 'device' in entity_types:
            indicators.append("Same device used for multiple applications")
        
        return indicators
    
    def add_network_link(self, application_id, entity_type, entity_value, link_strength=1):
        """Add a network link for an application"""
        conn = get_db_connection()
        conn.execute('''
            INSERT OR REPLACE INTO network_links 
            (application_id, entity_type, entity_value, link_strength)
            VALUES (?, ?, ?, ?)
        ''', (application_id, entity_type, entity_value, link_strength))
        conn.commit()
        conn.close()
    
    def analyze_application_network(self, application_data):
        """
        Analyze network connections for a new application
        Returns: network risk assessment
        """
        conn = get_db_connection()
        
        # Check for existing connections
        connections = {
            'aadhaar': [],
            'phone': [],
            'ip_address': [],
            'device': [],
            'bank_account': []
        }
        
        # Check Aadhaar connections
        if application_data.get('aadhaar'):
            aadhaar_links = conn.execute('''
                SELECT a.id, a.name, a.classification, nl.link_strength
                FROM network_links nl
                JOIN applications a ON nl.application_id = a.id
                WHERE nl.entity_type = 'aadhaar' 
                AND nl.entity_value = ?
            ''', (application_data['aadhaar'],)).fetchall()
            connections['aadhaar'] = [dict(l) for l in aadhaar_links]
        
        # Check phone connections
        if application_data.get('phone'):
            phone_links = conn.execute('''
                SELECT a.id, a.name, a.classification, nl.link_strength
                FROM network_links nl
                JOIN applications a ON nl.application_id = a.id
                WHERE nl.entity_type = 'phone' 
                AND nl.entity_value = ?
            ''', (application_data['phone'],)).fetchall()
            connections['phone'] = [dict(l) for l in phone_links]
        
        conn.close()
        
        # Calculate network risk
        total_connections = sum(len(v) for v in connections.values())
        risk_score = min(100, total_connections * 15)
        
        return {
            'connections': connections,
            'total_connections': total_connections,
            'network_risk_score': risk_score,
            'is_part_of_ring': total_connections >= 2,
            'recommendation': 'Investigate' if risk_score > 40 else 'Monitor'
        }
    
    def get_network_statistics(self):
        """Get overall network analysis statistics"""
        conn = get_db_connection()
        
        # Total network links
        total_links = conn.execute('SELECT COUNT(*) FROM network_links').fetchone()[0]
        
        # Unique entities
        unique_entities = conn.execute('SELECT COUNT(DISTINCT entity_value) FROM network_links').fetchone()[0]
        
        # Most connected entities
        top_entities = conn.execute('''
            SELECT entity_type, entity_value, COUNT(*) as connection_count
            FROM network_links
            GROUP BY entity_type, entity_value
            HAVING connection_count > 1
            ORDER BY connection_count DESC
            LIMIT 10
        ''').fetchall()
        
        # Detected fraud rings
        fraud_rings = self.detect_fraud_rings(min_ring_size=3)
        
        conn.close()
        
        return {
            'total_links': total_links,
            'unique_entities': unique_entities,
            'top_connected_entities': [dict(e) for e in top_entities],
            'detected_rings': len(fraud_rings),
            'fraud_rings': fraud_rings[:5],  # Top 5 rings
            'average_connections_per_entity': total_links / max(unique_entities, 1)
        }


# Global network analyzer instance
network_analyzer = NetworkAnalyzer()
