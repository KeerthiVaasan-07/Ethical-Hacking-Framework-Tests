"""
HTML Report Generator
Creates beautiful, professional HTML security reports with charts and visualizations
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Any
from core.tester_base import CategoryReport


class HTMLReportGenerator:
    """Generates comprehensive HTML security reports"""
    
    def __init__(self):
        self.template = self._get_html_template()
    
    def generate_report(self, reports: List[CategoryReport], 
                       config: Dict[str, Any],
                       output_path: str = 'reports/security_report.html') -> str:
        """
        Generate HTML report from test results
        
        Args:
            reports: List of CategoryReport objects
            config: Configuration dictionary
            output_path: Where to save the HTML file
            
        Returns:
            Path to generated report
        """
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Calculate summary statistics
        summary = self._calculate_summary(reports)
        
        # Generate HTML sections
        html_content = self.template.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            provider=config.get('provider', 'Unknown'),
            model=config.get('model', 'Unknown'),
            overall_risk_score=summary['overall_risk_score'],
            risk_level_color=self._get_risk_color(summary['overall_risk_score']),
            risk_level_text=self._get_risk_level(summary['overall_risk_score']),
            total_tests=summary['total_tests'],
            total_vulnerabilities=summary['total_vulnerabilities'],
            critical_count=summary['critical_count'],
            high_count=summary['high_count'],
            medium_count=summary['medium_count'],
            low_count=summary['low_count'],
            pass_rate=summary['pass_rate'],
            category_cards=self._generate_category_cards(reports),
            detailed_findings=self._generate_detailed_findings(reports),
            chart_data=self._generate_chart_data(reports),
            recommendations=self._generate_recommendations(reports, summary)
        )
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _calculate_summary(self, reports: List[CategoryReport]) -> Dict[str, Any]:
        """Calculate summary statistics"""
        total_tests = sum(r.total_tests for r in reports)
        total_vulns = sum(r.vulnerabilities_found for r in reports)
        
        critical = sum(r.critical_count for r in reports)
        high = sum(r.high_count for r in reports)
        medium = sum(r.medium_count for r in reports)
        low = sum(r.low_count for r in reports)
        
        # Calculate overall risk score (0-10)
        if reports:
            overall_risk = max(r.overall_risk_score for r in reports)
        else:
            overall_risk = 0.0
        
        pass_rate = ((total_tests - total_vulns) / total_tests * 100) if total_tests > 0 else 100
        
        return {
            'total_tests': total_tests,
            'total_vulnerabilities': total_vulns,
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low,
            'overall_risk_score': round(overall_risk, 1),
            'pass_rate': round(pass_rate, 1)
        }
    
    def _get_risk_color(self, risk_score: float) -> str:
        """Get color based on risk score"""
        if risk_score >= 7:
            return '#dc3545'  # Red
        elif risk_score >= 5:
            return '#fd7e14'  # Orange
        elif risk_score >= 3:
            return '#ffc107'  # Yellow
        else:
            return '#28a745'  # Green
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level text"""
        if risk_score >= 7:
            return 'CRITICAL'
        elif risk_score >= 5:
            return 'HIGH'
        elif risk_score >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8',
            'info': '#6c757d'
        }
        return colors.get(severity.lower(), '#6c757d')
    
    def _generate_category_cards(self, reports: List[CategoryReport]) -> str:
        """Generate category summary cards"""
        cards_html = []
        
        for report in reports:
            risk_color = self._get_risk_color(report.overall_risk_score)
            
            card = f'''
            <div class="category-card">
                <div class="category-header">
                    <h3>{report.category}</h3>
                    <div class="risk-badge" style="background-color: {risk_color};">
                        {report.overall_risk_score}/10
                    </div>
                </div>
                <div class="category-stats">
                    <div class="stat">
                        <span class="stat-label">Tests Run</span>
                        <span class="stat-value">{report.total_tests}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Vulnerabilities</span>
                        <span class="stat-value">{report.vulnerabilities_found}</span>
                    </div>
                </div>
                <div class="severity-breakdown">
                    <div class="severity-item">
                        <span class="severity-dot" style="background-color: #dc3545;"></span>
                        <span>Critical: {report.critical_count}</span>
                    </div>
                    <div class="severity-item">
                        <span class="severity-dot" style="background-color: #fd7e14;"></span>
                        <span>High: {report.high_count}</span>
                    </div>
                    <div class="severity-item">
                        <span class="severity-dot" style="background-color: #ffc107;"></span>
                        <span>Medium: {report.medium_count}</span>
                    </div>
                    <div class="severity-item">
                        <span class="severity-dot" style="background-color: #17a2b8;"></span>
                        <span>Low: {report.low_count}</span>
                    </div>
                </div>
            </div>
            '''
            cards_html.append(card)
        
        return '\n'.join(cards_html)
    
    def _generate_detailed_findings(self, reports: List[CategoryReport]) -> str:
        """Generate detailed findings section"""
        findings_html = []
        
        for report in reports:
            # Only show vulnerabilities
            vulnerabilities = [r for r in report.test_results if r.vulnerable]
            
            if not vulnerabilities:
                continue
            
            category_section = f'''
            <div class="findings-category">
                <h3>{report.category} - {len(vulnerabilities)} Vulnerabilities Found</h3>
            '''
            
            for idx, vuln in enumerate(vulnerabilities, 1):
                severity_color = self._get_severity_color(vuln.severity)
                
                finding = f'''
                <div class="finding-card">
                    <div class="finding-header">
                        <div>
                            <span class="severity-badge" style="background-color: {severity_color};">
                                {vuln.severity.upper()}
                            </span>
                            <span class="finding-title">{vuln.test_name}</span>
                        </div>
                        <span class="confidence-badge">
                            {int(vuln.confidence * 100)}% Confidence
                        </span>
                    </div>
                    
                    <div class="finding-description">
                        {vuln.description}
                    </div>
                    
                    <div class="finding-section">
                        <h4>Attack Payload:</h4>
                        <pre class="code-block">{self._html_escape(vuln.attack_payload)}</pre>
                    </div>
                    
                    <div class="finding-section">
                        <h4>LLM Response:</h4>
                        <pre class="code-block">{self._html_escape(vuln.llm_response)}</pre>
                    </div>
                    
                    <div class="finding-section">
                        <h4>Evidence:</h4>
                        <p class="evidence">{vuln.evidence}</p>
                    </div>
                    
                    <div class="finding-section mitigation">
                        <h4>Recommended Mitigation:</h4>
                        <pre class="mitigation-text">{vuln.mitigation}</pre>
                    </div>
                    
                    <div class="finding-meta">
                        <span>Response Time: {vuln.response_time:.2f}s</span>
                        <span>Tested: {vuln.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</span>
                    </div>
                </div>
                '''
                category_section += finding
            
            category_section += '</div>'
            findings_html.append(category_section)
        
        return '\n'.join(findings_html) if findings_html else '<p>No vulnerabilities found! ✅</p>'
    
    def _generate_chart_data(self, reports: List[CategoryReport]) -> str:
        """Generate JavaScript chart data"""
        # Category names and risk scores
        categories = [r.category for r in reports]
        risk_scores = [r.overall_risk_score for r in reports]
        
        # Severity distribution
        severity_data = {
            'critical': sum(r.critical_count for r in reports),
            'high': sum(r.high_count for r in reports),
            'medium': sum(r.medium_count for r in reports),
            'low': sum(r.low_count for r in reports)
        }
        
        chart_data = f'''
        const categoryData = {json.dumps(categories)};
        const riskScores = {json.dumps(risk_scores)};
        const severityData = {json.dumps(severity_data)};
        '''
        
        return chart_data
    
    def _generate_recommendations(self, reports: List[CategoryReport], 
                                  summary: Dict[str, Any]) -> str:
        """Generate recommendations section"""
        recommendations = []
        
        # Overall recommendations based on risk score
        if summary['overall_risk_score'] >= 7:
            recommendations.append({
                'priority': 'URGENT',
                'title': 'Critical Vulnerabilities Detected',
                'text': 'Immediate action required. Your LLM has critical security vulnerabilities that could be exploited for significant harm.',
                'color': '#dc3545'
            })
        elif summary['overall_risk_score'] >= 5:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Significant Security Gaps',
                'text': 'Your LLM has notable security issues that should be addressed promptly to prevent exploitation.',
                'color': '#fd7e14'
            })
        elif summary['overall_risk_score'] >= 3:
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Security Improvements Needed',
                'text': 'Some vulnerabilities detected. Consider implementing recommended mitigations to improve security posture.',
                'color': '#ffc107'
            })
        else:
            recommendations.append({
                'priority': 'LOW',
                'title': 'Good Security Posture',
                'text': 'Your LLM demonstrates good security practices. Continue monitoring and stay updated on new attack vectors.',
                'color': '#28a745'
            })
        
        # Specific recommendations
        if summary['critical_count'] > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'title': f'{summary["critical_count"]} Critical Issues',
                'text': 'Review all critical findings immediately and implement mitigations before production deployment.',
                'color': '#dc3545'
            })
        
        # Category-specific
        for report in reports:
            if report.critical_count > 0 or report.high_count > 0:
                recommendations.append({
                    'priority': 'ACTION REQUIRED',
                    'title': f'{report.category} Vulnerabilities',
                    'text': f'Address {report.vulnerabilities_found} vulnerabilities in {report.category}. See detailed findings below.',
                    'color': '#fd7e14'
                })
        
        # Generate HTML
        rec_html = []
        for rec in recommendations[:5]:  # Limit to top 5
            rec_html.append(f'''
            <div class="recommendation-card" style="border-left: 4px solid {rec['color']};">
                <div class="rec-priority" style="color: {rec['color']};">{rec['priority']}</div>
                <h4>{rec['title']}</h4>
                <p>{rec['text']}</p>
            </div>
            ''')
        
        return '\n'.join(rec_html)
    
    def _html_escape(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
    
    def _get_html_template(self) -> str:
        """Get HTML template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM Security Test Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            opacity: 0.9;
            margin-top: 15px;
        }}
        
        .executive-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .summary-card .label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .risk-score {{
            font-size: 3em !important;
        }}
        
        .categories {{
            padding: 30px;
        }}
        
        .categories h2 {{
            margin-bottom: 25px;
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .category-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .category-card {{
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .category-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.1);
        }}
        
        .category-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .category-header h3 {{
            color: #333;
            font-size: 1.2em;
        }}
        
        .risk-badge {{
            background: #667eea;
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: bold;
        }}
        
        .category-stats {{
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }}
        
        .stat {{
            text-align: center;
        }}
        
        .stat-label {{
            display: block;
            font-size: 0.85em;
            color: #6c757d;
            margin-bottom: 5px;
        }}
        
        .stat-value {{
            display: block;
            font-size: 1.8em;
            font-weight: bold;
            color: #333;
        }}
        
        .severity-breakdown {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e9ecef;
        }}
        
        .severity-item {{
            display: flex;
            align-items: center;
            padding: 5px 0;
        }}
        
        .severity-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 10px;
        }}
        
        .charts {{
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .charts h2 {{
            margin-bottom: 25px;
            color: #333;
        }}
        
        .chart-container {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        canvas {{
            max-height: 300px;
        }}
        
        .findings {{
            padding: 30px;
        }}
        
        .findings h2 {{
            margin-bottom: 25px;
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .findings-category {{
            margin-bottom: 40px;
        }}
        
        .findings-category h3 {{
            color: #667eea;
            margin-bottom: 20px;
        }}
        
        .finding-card {{
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
            margin-right: 10px;
        }}
        
        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
        }}
        
        .confidence-badge {{
            background: #e9ecef;
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 0.9em;
            color: #495057;
        }}
        
        .finding-description {{
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #667eea;
            margin-bottom: 20px;
            font-style: italic;
        }}
        
        .finding-section {{
            margin-bottom: 20px;
        }}
        
        .finding-section h4 {{
            color: #495057;
            margin-bottom: 10px;
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .code-block {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            border: 1px solid #dee2e6;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .evidence {{
            background: #fff3cd;
            padding: 12px;
            border-left: 4px solid #ffc107;
            color: #856404;
        }}
        
        .mitigation {{
            background: #d1ecf1;
            padding: 15px;
            border-radius: 4px;
        }}
        
        .mitigation h4 {{
            color: #0c5460;
        }}
        
        .mitigation-text {{
            background: white;
            padding: 15px;
            border-radius: 4px;
            border: 1px solid #bee5eb;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.6;
            white-space: pre-wrap;
        }}
        
        .finding-meta {{
            display: flex;
            justify-content: space-between;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e9ecef;
            font-size: 0.85em;
            color: #6c757d;
        }}
        
        .recommendations {{
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .recommendations h2 {{
            margin-bottom: 25px;
            color: #333;
        }}
        
        .recommendation-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
        }}
        
        .rec-priority {{
            font-weight: bold;
            font-size: 0.85em;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .recommendation-card h4 {{
            margin-bottom: 10px;
            color: #333;
        }}
        
        .footer {{
            background: #343a40;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ LLM Security Test Report</h1>
            <div class="meta">
                <p>Generated: {timestamp}</p>
                <p>Provider: {provider} | Model: {model}</p>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="executive-summary">
            <div class="summary-card">
                <div class="label">Overall Risk Score</div>
                <div class="value risk-score" style="color: {risk_level_color};">
                    {overall_risk_score}
                </div>
                <div class="label" style="color: {risk_level_color}; font-weight: bold;">
                    {risk_level_text}
                </div>
            </div>
            
            <div class="summary-card">
                <div class="label">Total Tests</div>
                <div class="value">{total_tests}</div>
                <div class="label">Pass Rate: {pass_rate}%</div>
            </div>
            
            <div class="summary-card">
                <div class="label">Vulnerabilities</div>
                <div class="value" style="color: #dc3545;">{total_vulnerabilities}</div>
                <div class="label">Issues Found</div>
            </div>
            
            <div class="summary-card">
                <div class="label">Critical</div>
                <div class="value" style="color: #dc3545;">{critical_count}</div>
                <div class="label">Urgent Action</div>
            </div>
            
            <div class="summary-card">
                <div class="label">High</div>
                <div class="value" style="color: #fd7e14;">{high_count}</div>
                <div class="label">Important</div>
            </div>
            
            <div class="summary-card">
                <div class="label">Medium</div>
                <div class="value" style="color: #ffc107;">{medium_count}</div>
                <div class="label">Moderate</div>
            </div>
        </div>
        
        <!-- Category Cards -->
        <div class="categories">
            <h2>Test Categories</h2>
            <div class="category-grid">
                {category_cards}
            </div>
        </div>
        
        <!-- Charts -->
        <div class="charts">
            <h2>Visualizations</h2>
            
            <div class="chart-container">
                <canvas id="riskChart"></canvas>
            </div>
            
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        
        <!-- Recommendations -->
        <div class="recommendations">
            <h2>Key Recommendations</h2>
            {recommendations}
        </div>
        
        <!-- Detailed Findings -->
        <div class="findings">
            <h2>Detailed Findings</h2>
            {detailed_findings}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by LLM Security Testing Framework</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                This report is for security assessment purposes only.
            </p>
        </div>
    </div>
    
    <script>
        {chart_data}
        
        // Risk Scores by Category Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {{
            type: 'bar',
            data: {{
                labels: categoryData,
                datasets: [{{
                    label: 'Risk Score (0-10)',
                    data: riskScores,
                    backgroundColor: riskScores.map(score => {{
                        if (score >= 7) return 'rgba(220, 53, 69, 0.8)';
                        if (score >= 5) return 'rgba(253, 126, 20, 0.8)';
                        if (score >= 3) return 'rgba(255, 193, 7, 0.8)';
                        return 'rgba(40, 167, 69, 0.8)';
                    }}),
                    borderColor: riskScores.map(score => {{
                        if (score >= 7) return 'rgba(220, 53, 69, 1)';
                        if (score >= 5) return 'rgba(253, 126, 20, 1)';
                        if (score >= 3) return 'rgba(255, 193, 7, 1)';
                        return 'rgba(40, 167, 69, 1)';
                    }}),
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 10
                    }}
                }},
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Risk Score by Category'
                    }},
                    legend: {{
                        display: false
                    }}
                }}
            }}
        }});
        
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [
                        severityData.critical,
                        severityData.high,
                        severityData.medium,
                        severityData.low
                    ],
                    backgroundColor: [
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(253, 126, 20, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(23, 162, 184, 0.8)'
                    ],
                    borderColor: [
                        'rgba(220, 53, 69, 1)',
                        'rgba(253, 126, 20, 1)',
                        'rgba(255, 193, 7, 1)',
                        'rgba(23, 162, 184, 1)'
                    ],
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Vulnerability Distribution by Severity'
                    }},
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>'''