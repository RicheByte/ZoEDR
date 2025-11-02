#!/usr/bin/env python3
# zoedr_dashboard_advanced.py - ZoEDR Advanced Dashboard with Live Graphs

import json
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time # For sleep in debug
from dash import Dash, html, dcc
import plotly.express as px
import plotly.graph_objects as go
from dash.dependencies import Input, Output
import dash_bootstrap_components as dbc

# --- Configuration ---
ALERT_FILE = "/var/log/zoedr/alerts.json" # Consistent with zoedr_common.h
REFRESH_INTERVAL_MS = 5000 # Refresh every 5 seconds
MAX_ALERTS_DISPLAY = 50 # Number of latest alerts to show in the list

# --- Color Palette (Modern Cybersecurity Theme) ---
COLOR_PALETTE = {
    'background': '#0a0e27',
    'card_bg': '#1a1f3a',
    'card_border': '#2d3561',
    'text_primary': '#e8eaf6',
    'text_secondary': '#b0b8d4',
    'accent_blue': '#00d4ff',
    'accent_cyan': '#00ffea',
    'accent_purple': '#9d4edd',
    'severity': {
        'info': '#00d4ff',
        'low': '#26c6da',
        'medium': '#ffa726',
        'high': '#ff5252',
        'critical': '#d50000'
    },
    'graph_bg': '#151a35',
    'grid_color': '#2d3561'
}

# --- Helper Function to Load Alerts ---
def load_alerts():
    data = []
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, 'r') as f:
            for line in f:
                try:
                    alert = json.loads(line.strip())
                    # Ensure all expected keys are present with defaults
                    alert.setdefault('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    alert.setdefault('host', 'Unknown')
                    alert.setdefault('alert_type', 'UNKNOWN_ALERT_TYPE')
                    alert.setdefault('pid', 0)
                    alert.setdefault('process_name', 'N/A')
                    alert.setdefault('threat_score_total', 0)
                    alert.setdefault('severity', 'info')
                    alert.setdefault('details', 'No additional details.')
                    data.append(alert)
                except json.JSONDecodeError:
                    # print(f"Skipping malformed JSON line: {line.strip()}")
                    continue
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    if not df.empty:
        # Convert timestamp to datetime objects
        df['timestamp_dt'] = pd.to_datetime(df['timestamp'], errors='coerce')
        # Filter out rows where timestamp conversion failed
        df = df.dropna(subset=['timestamp_dt'])
        # Sort by timestamp to ensure proper trend analysis
        df = df.sort_values(by='timestamp_dt', ascending=True)
        # Add hour and day columns for analysis
        df['hour'] = df['timestamp_dt'].dt.hour
        df['day_of_week'] = df['timestamp_dt'].dt.day_name()
        df['date'] = df['timestamp_dt'].dt.date
    return df

# --- Helper Function to Calculate KPIs ---
def calculate_kpis(df):
    if df.empty:
        return {
            'total_alerts': 0,
            'critical_alerts': 0,
            'unique_hosts': 0,
            'avg_threat_score': 0,
            'alerts_last_hour': 0,
            'top_process': 'N/A'
        }
    
    now = datetime.now()
    one_hour_ago = now - timedelta(hours=1)
    recent_alerts = df[df['timestamp_dt'] >= one_hour_ago]
    
    kpis = {
        'total_alerts': len(df),
        'critical_alerts': len(df[df['severity'] == 'critical']),
        'unique_hosts': df['host'].nunique(),
        'avg_threat_score': round(df['threat_score_total'].mean(), 2),
        'alerts_last_hour': len(recent_alerts),
        'top_process': df['process_name'].value_counts().index[0] if len(df) > 0 else 'N/A'
    }
    return kpis

# --- Initialize Dash App ---
# Using a Bootstrap theme for a professional look
app = Dash(__name__, external_stylesheets=[dbc.themes.CYBORG])
app.title = "ZoEDR Threat Dashboard - Zeta Realm Security"

# --- Layout Definition ---
app.layout = dbc.Container([
    # Header
    dbc.Row(
        dbc.Col(
            html.Div([
                html.H1("🐉 ZoEDR Threat Intelligence Dashboard", 
                       className="text-center mb-1",
                       style={'color': COLOR_PALETTE['accent_cyan'], 'fontWeight': '700'}),
                html.P("Real-time Endpoint Detection & Response Monitoring",
                      className="text-center text-muted mb-4")
            ])
        )
    ),
    
    # KPI Cards Row
    dbc.Row([
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-shield-alt fa-2x mb-2", 
                              style={'color': COLOR_PALETTE['accent_blue']}),
                        html.H3(id='kpi-total-alerts', className="mb-0"),
                        html.P("Total Alerts", className="text-muted small mb-0")
                    ], className="text-center")
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg'], 
                     'borderLeft': f"4px solid {COLOR_PALETTE['accent_blue']}"}, 
               className="mb-3 shadow-sm"),
            md=3, sm=6
        ),
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-exclamation-triangle fa-2x mb-2", 
                              style={'color': COLOR_PALETTE['severity']['critical']}),
                        html.H3(id='kpi-critical-alerts', className="mb-0"),
                        html.P("Critical Alerts", className="text-muted small mb-0")
                    ], className="text-center")
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg'],
                     'borderLeft': f"4px solid {COLOR_PALETTE['severity']['critical']}"}, 
               className="mb-3 shadow-sm"),
            md=3, sm=6
        ),
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-server fa-2x mb-2", 
                              style={'color': COLOR_PALETTE['accent_purple']}),
                        html.H3(id='kpi-unique-hosts', className="mb-0"),
                        html.P("Monitored Hosts", className="text-muted small mb-0")
                    ], className="text-center")
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg'],
                     'borderLeft': f"4px solid {COLOR_PALETTE['accent_purple']}"}, 
               className="mb-3 shadow-sm"),
            md=3, sm=6
        ),
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-chart-line fa-2x mb-2", 
                              style={'color': COLOR_PALETTE['severity']['medium']}),
                        html.H3(id='kpi-avg-score', className="mb-0"),
                        html.P("Avg Threat Score", className="text-muted small mb-0")
                    ], className="text-center")
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg'],
                     'borderLeft': f"4px solid {COLOR_PALETTE['severity']['medium']}"}, 
               className="mb-3 shadow-sm"),
            md=3, sm=6
        )
    ]),
    
    # Main Content Row 1
    dbc.Row([
        # Threat Trends
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-chart-area me-2"),
                    "Threat Activity Timeline"
                ], style={'backgroundColor': COLOR_PALETTE['card_bg'], 
                         'borderBottom': f"2px solid {COLOR_PALETTE['accent_blue']}", 
                         'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='trend-graph', config={'displayModeBar': False})
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg']}, className="mb-3 shadow"),
        ], md=8),
        
        # Severity Distribution
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-pie-chart me-2"),
                    "Severity Distribution"
                ], style={'backgroundColor': COLOR_PALETTE['card_bg'], 
                         'borderBottom': f"2px solid {COLOR_PALETTE['accent_purple']}", 
                         'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='severity-pie', config={'displayModeBar': False})
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg']}, className="mb-3 shadow"),
        ], md=4)
    ]),
    
    # Main Content Row 2
    dbc.Row([
        # Attack Types Bar Chart
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-bug me-2"),
                    "Top Attack Vectors"
                ], style={'backgroundColor': COLOR_PALETTE['card_bg'], 
                         'borderBottom': f"2px solid {COLOR_PALETTE['accent_cyan']}", 
                         'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='type-graph', config={'displayModeBar': False})
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg']}, className="mb-3 shadow"),
        ], md=6),
        
        # Process Activity
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-cogs me-2"),
                    "Top Flagged Processes"
                ], style={'backgroundColor': COLOR_PALETTE['card_bg'], 
                         'borderBottom': f"2px solid {COLOR_PALETTE['severity']['medium']}", 
                         'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='process-graph', config={'displayModeBar': False})
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg']}, className="mb-3 shadow"),
        ], md=6)
    ]),
    
    # Main Content Row 3
    dbc.Row([
        # Hourly Heatmap
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-calendar-alt me-2"),
                    "Activity Heatmap (Hour × Day)"
                ], style={'backgroundColor': COLOR_PALETTE['card_bg'], 
                         'borderBottom': f"2px solid {COLOR_PALETTE['accent_purple']}", 
                         'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='heatmap-graph', config={'displayModeBar': False})
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg']}, className="mb-3 shadow"),
        ], md=8),
        
        # Top Hosts Table
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-network-wired me-2"),
                    "Most Targeted Hosts"
                ], style={'backgroundColor': COLOR_PALETTE['card_bg'], 
                         'borderBottom': f"2px solid {COLOR_PALETTE['severity']['high']}", 
                         'fontWeight': '600'}),
                dbc.CardBody([
                    html.Div(id='hosts-table', style={'maxHeight': '400px', 'overflowY': 'auto'})
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg']}, className="mb-3 shadow"),
        ], md=4)
    ]),
    
    # Latest Alerts Section
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-bell me-2"),
                    "Recent Alerts Feed"
                ], style={'backgroundColor': COLOR_PALETTE['card_bg'], 
                         'borderBottom': f"2px solid {COLOR_PALETTE['severity']['critical']}", 
                         'fontWeight': '600'}),
                dbc.CardBody([
                    html.Div(id='alerts-container', style={'maxHeight': '500px', 'overflowY': 'auto'})
                ])
            ], style={'backgroundColor': COLOR_PALETTE['card_bg']}, className="mb-3 shadow")
        ])
    ]),

    # Hidden interval component for auto-refresh
    dcc.Interval(
        id='interval-component',
        interval=REFRESH_INTERVAL_MS,
        n_intervals=0
    )
], fluid=True, style={'backgroundColor': COLOR_PALETTE['background'], 'minHeight': '100vh', 'padding': '20px'})

# --- Callbacks ---

# Callback to update KPI cards
@app.callback(
    [Output('kpi-total-alerts', 'children'),
     Output('kpi-critical-alerts', 'children'),
     Output('kpi-unique-hosts', 'children'),
     Output('kpi-avg-score', 'children')],
    Input('interval-component', 'n_intervals')
)
def update_kpis(n):
    df = load_alerts()
    kpis = calculate_kpis(df)
    return (
        str(kpis['total_alerts']),
        str(kpis['critical_alerts']),
        str(kpis['unique_hosts']),
        str(kpis['avg_threat_score'])
    )

# Callback to update the list of latest alerts
@app.callback(
    Output('alerts-container', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_alerts_list(n):
    df = load_alerts()
    alerts_html = []

    if not df.empty:
        # Get the latest MAX_ALERTS_DISPLAY alerts
        latest_alerts = df.tail(MAX_ALERTS_DISPLAY).to_dict('records')
        
        for alert in reversed(latest_alerts): # Display latest first
            severity_color = COLOR_PALETTE['severity'].get(alert['severity'], '#888888')
            
            # Icon based on severity
            icon_map = {
                'critical': 'fa-skull-crossbones',
                'high': 'fa-exclamation-circle',
                'medium': 'fa-exclamation-triangle',
                'low': 'fa-info-circle',
                'info': 'fa-info'
            }
            icon = icon_map.get(alert['severity'], 'fa-question-circle')
            
            alerts_html.append(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className=f"fas {icon} me-2", style={'color': severity_color}),
                            html.Strong(f"{alert['alert_type']}", style={'color': severity_color}),
                            html.Span(f" • {alert['timestamp']}", className="text-muted small ms-2")
                        ], className="mb-2"),
                        html.Div([
                            html.Span([
                                html.I(className="fas fa-server me-1", style={'fontSize': '0.8em'}),
                                f"{alert['host']}"
                            ], className="me-3 small"),
                            html.Span([
                                html.I(className="fas fa-hashtag me-1", style={'fontSize': '0.8em'}),
                                f"PID: {alert['pid']}"
                            ], className="me-3 small"),
                            html.Span([
                                html.I(className="fas fa-cog me-1", style={'fontSize': '0.8em'}),
                                f"{alert['process_name']}"
                            ], className="small")
                        ], className="mb-2 text-muted"),
                        html.Div([
                            dbc.Badge(f"{alert['severity'].upper()}", 
                                    color="danger" if alert['severity'] in ['critical', 'high'] else 
                                          "warning" if alert['severity'] == 'medium' else "info",
                                    className="me-2"),
                            dbc.Badge(f"Score: {alert['threat_score_total']}", color="secondary")
                        ], className="mb-2"),
                        html.P(alert['details'], className="small mb-0 text-muted", 
                              style={'fontSize': '0.85em'})
                    ])
                ], style={'backgroundColor': COLOR_PALETTE['graph_bg'],
                         'borderLeft': f'4px solid {severity_color}',
                         'marginBottom': '10px'})
            )
    else:
        alerts_html.append(
            html.Div([
                html.I(className="fas fa-check-circle fa-3x mb-3", 
                      style={'color': COLOR_PALETTE['severity']['low']}),
                html.P("No alerts detected. System status: All clear.", 
                      className="text-muted")
            ], className="text-center py-5")
        )
    
    return alerts_html

# Callback to update the Threat Trends graph
@app.callback(
    Output('trend-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_trend_graph(n):
    df = load_alerts()
    if df.empty:
        return create_empty_figure('No threat data available')
    
    # Group by 1-minute intervals and severity
    df_grouped = df.groupby([pd.Grouper(key='timestamp_dt', freq='1T'), 'severity']).size().reset_index(name='count')
    
    # Order severities for consistent legend and color mapping
    severity_order = ['info', 'low', 'medium', 'high', 'critical']
    df_grouped['severity'] = pd.Categorical(df_grouped['severity'], categories=severity_order, ordered=True)
    df_grouped = df_grouped.sort_values('severity')

    fig = px.area(df_grouped, x='timestamp_dt', y='count', color='severity',
                  labels={'timestamp_dt': 'Time', 'count': 'Alerts', 'severity': 'Severity'},
                  color_discrete_map=COLOR_PALETTE['severity'])
    
    fig.update_layout(
        paper_bgcolor=COLOR_PALETTE['graph_bg'],
        plot_bgcolor=COLOR_PALETTE['graph_bg'],
        font_color=COLOR_PALETTE['text_primary'],
        xaxis=dict(showgrid=True, gridcolor=COLOR_PALETTE['grid_color']),
        yaxis=dict(showgrid=True, gridcolor=COLOR_PALETTE['grid_color']),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hovermode='x unified',
        margin=dict(l=40, r=40, t=40, b=40)
    )
    return fig

# Callback to update severity pie chart
@app.callback(
    Output('severity-pie', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_severity_pie(n):
    df = load_alerts()
    if df.empty:
        return create_empty_figure('No severity data')
    
    severity_counts = df['severity'].value_counts().reset_index()
    severity_counts.columns = ['severity', 'count']
    
    fig = go.Figure(data=[go.Pie(
        labels=severity_counts['severity'],
        values=severity_counts['count'],
        hole=0.4,
        marker=dict(colors=[COLOR_PALETTE['severity'][sev] for sev in severity_counts['severity']]),
        textinfo='label+percent',
        textfont=dict(size=12, color=COLOR_PALETTE['text_primary'])
    )])
    
    fig.update_layout(
        paper_bgcolor=COLOR_PALETTE['graph_bg'],
        plot_bgcolor=COLOR_PALETTE['graph_bg'],
        font_color=COLOR_PALETTE['text_primary'],
        showlegend=False,
        margin=dict(l=20, r=20, t=20, b=20),
        height=300
    )
    return fig

# Callback to update the Top Attack Types graph
@app.callback(
    Output('type-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_type_graph(n):
    df = load_alerts()
    if df.empty:
        return create_empty_figure('No attack type data')

    df_type = df['alert_type'].value_counts().head(10).reset_index()
    df_type.columns = ['alert_type', 'count']
    
    fig = go.Figure(data=[go.Bar(
        x=df_type['count'],
        y=df_type['alert_type'],
        orientation='h',
        marker=dict(
            color=df_type['count'],
            colorscale='Turbo',
            showscale=False
        ),
        text=df_type['count'],
        textposition='auto',
    )])
    
    fig.update_layout(
        paper_bgcolor=COLOR_PALETTE['graph_bg'],
        plot_bgcolor=COLOR_PALETTE['graph_bg'],
        font_color=COLOR_PALETTE['text_primary'],
        xaxis=dict(showgrid=True, gridcolor=COLOR_PALETTE['grid_color'], title='Count'),
        yaxis=dict(showgrid=False, title=''),
        margin=dict(l=40, r=40, t=40, b=40),
        height=400
    )
    return fig

# Callback to update process activity graph
@app.callback(
    Output('process-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_process_graph(n):
    df = load_alerts()
    if df.empty:
        return create_empty_figure('No process data')
    
    df_process = df['process_name'].value_counts().head(10).reset_index()
    df_process.columns = ['process', 'count']
    
    fig = go.Figure(data=[go.Bar(
        x=df_process['count'],
        y=df_process['process'],
        orientation='h',
        marker=dict(
            color=COLOR_PALETTE['accent_purple'],
            line=dict(color=COLOR_PALETTE['accent_cyan'], width=1)
        ),
        text=df_process['count'],
        textposition='auto',
    )])
    
    fig.update_layout(
        paper_bgcolor=COLOR_PALETTE['graph_bg'],
        plot_bgcolor=COLOR_PALETTE['graph_bg'],
        font_color=COLOR_PALETTE['text_primary'],
        xaxis=dict(showgrid=True, gridcolor=COLOR_PALETTE['grid_color'], title='Alert Count'),
        yaxis=dict(showgrid=False, title=''),
        margin=dict(l=40, r=40, t=40, b=40),
        height=400
    )
    return fig

# Callback for hourly heatmap
@app.callback(
    Output('heatmap-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_heatmap(n):
    df = load_alerts()
    if df.empty:
        return create_empty_figure('No temporal data')
    
    # Create pivot table for heatmap
    day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    heatmap_data = df.groupby(['day_of_week', 'hour']).size().reset_index(name='count')
    heatmap_pivot = heatmap_data.pivot(index='day_of_week', columns='hour', values='count').fillna(0)
    
    # Reorder days
    heatmap_pivot = heatmap_pivot.reindex([day for day in day_order if day in heatmap_pivot.index])
    
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_pivot.values,
        x=[f"{h:02d}:00" for h in heatmap_pivot.columns],
        y=heatmap_pivot.index,
        colorscale='Plasma',
        colorbar=dict(title="Alerts"),
        hoverongaps=False
    ))
    
    fig.update_layout(
        paper_bgcolor=COLOR_PALETTE['graph_bg'],
        plot_bgcolor=COLOR_PALETTE['graph_bg'],
        font_color=COLOR_PALETTE['text_primary'],
        xaxis=dict(title='Hour of Day', side='bottom'),
        yaxis=dict(title='Day of Week'),
        margin=dict(l=100, r=40, t=40, b=60),
        height=400
    )
    return fig

# Callback for top hosts table
@app.callback(
    Output('hosts-table', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_hosts_table(n):
    df = load_alerts()
    if df.empty:
        return html.P("No host data available", className="text-muted text-center py-4")
    
    host_stats = df.groupby('host').agg({
        'alert_type': 'count',
        'severity': lambda x: (x == 'critical').sum(),
        'threat_score_total': 'mean'
    }).reset_index()
    host_stats.columns = ['Host', 'Total Alerts', 'Critical', 'Avg Score']
    host_stats = host_stats.sort_values('Total Alerts', ascending=False).head(10)
    host_stats['Avg Score'] = host_stats['Avg Score'].round(1)
    
    table_rows = []
    for idx, row in host_stats.iterrows():
        table_rows.append(
            html.Div([
                html.Div([
                    html.Strong(row['Host'], style={'color': COLOR_PALETTE['accent_cyan']}),
                    html.Div([
                        dbc.Badge(f"{row['Total Alerts']} alerts", color="primary", className="me-1"),
                        dbc.Badge(f"{row['Critical']} critical", color="danger", className="me-1") if row['Critical'] > 0 else None,
                        dbc.Badge(f"Score: {row['Avg Score']}", color="secondary")
                    ], className="mt-1")
                ], style={'padding': '10px', 
                         'borderBottom': f"1px solid {COLOR_PALETTE['grid_color']}"})
            ])
        )
    
    return table_rows

# Helper function for empty figures
def create_empty_figure(message):
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper", yref="paper",
        x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=16, color=COLOR_PALETTE['text_secondary'])
    )
    fig.update_layout(
        paper_bgcolor=COLOR_PALETTE['graph_bg'],
        plot_bgcolor=COLOR_PALETTE['graph_bg'],
        xaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
        yaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
        margin=dict(l=40, r=40, t=40, b=40)
    )
    return fig


# --- Run the App ---
if __name__ == '__main__':
    # For development, you might want debug=True
    # For production, ensure debug=False and use a WSGI server like Gunicorn
    app.run(host='0.0.0.0', port=8888, debug=False)

