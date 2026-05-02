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

# --- Cyberpunk / Glassmorphism Theme ---
COLOR_PALETTE = {
    'background': '#02050f',
    'card_bg': 'rgba(15, 20, 45, 0.65)', # Semi-transparent for glassmorphism
    'card_border': 'rgba(0, 212, 255, 0.3)',
    'text_primary': '#e8eaf6',
    'text_secondary': '#b0b8d4',
    'accent_blue': '#00d4ff',
    'accent_cyan': '#00ffea',
    'accent_purple': '#b026ff',
    'severity': {
        'info': '#00d4ff',
        'low': '#00ffea',
        'medium': '#ffea00',
        'high': '#ff5252',
        'critical': '#ff003c'
    },
    'graph_bg': 'rgba(0,0,0,0)', # Transparent graph backgrounds
    'grid_color': 'rgba(45, 53, 97, 0.4)'
}

GLASS_STYLE = {
    'backgroundColor': COLOR_PALETTE['card_bg'],
    'backdropFilter': 'blur(12px)',
    'WebkitBackdropFilter': 'blur(12px)',
    'border': f"1px solid {COLOR_PALETTE['card_border']}",
    'boxShadow': '0 8px 32px 0 rgba(0, 212, 255, 0.1)',
    'borderRadius': '10px'
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
                html.H1("⚡ ZETA REALM: SUPERHUMAN SOC COMMAND", 
                       className="text-center mb-1",
                       style={'color': COLOR_PALETTE['accent_cyan'], 'fontWeight': '800', 'letterSpacing': '2px', 'textShadow': f"0 0 15px {COLOR_PALETTE['accent_cyan']}"}),
                html.P("Live Neural Threat Processing Engine",
                      className="text-center mb-4", style={'color': COLOR_PALETTE['accent_purple'], 'letterSpacing': '1px'})
            ])
        )
    ),
    
    # Audio Alert Element
    html.Audio(id='critical-alarm-audio', src='https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3', preload='auto'),

    # AI Analyst Feed
    dbc.Row(
        dbc.Col(
            html.Div([
                html.I(className="fas fa-brain fa-2x me-3", style={'color': COLOR_PALETTE['accent_purple'], 'textShadow': f"0 0 10px {COLOR_PALETTE['accent_purple']}"}),
                html.Span("AI Analyst Link: ", style={'color': COLOR_PALETTE['accent_purple'], 'fontWeight': 'bold', 'fontSize': '1.2rem'}),
                html.Span(id='ai-analyst-text', style={'color': COLOR_PALETTE['text_primary'], 'fontFamily': 'monospace', 'fontSize': '1.1rem'}),
            ], style={**GLASS_STYLE, 'padding': '15px', 'marginBottom': '25px', 'borderLeft': f"4px solid {COLOR_PALETTE['accent_purple']}"})
        )
    ),
    
    # KPI Cards Row
    dbc.Row([
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-shield-alt fa-2x mb-2", 
                               style={'color': COLOR_PALETTE['accent_blue'], 'textShadow': f"0 0 10px {COLOR_PALETTE['accent_blue']}"}),
                        html.H3(id='kpi-total-alerts', className="mb-0", style={'fontWeight': 'bold'}),
                        html.P("Total Alerts", className="text-muted small mb-0")
                    ], className="text-center")
                ])
            ], style={**GLASS_STYLE, 'borderLeft': f"4px solid {COLOR_PALETTE['accent_blue']}"}, 
               className="mb-3"),
            md=3, sm=6
        ),
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-biohazard fa-2x mb-2", 
                               style={'color': COLOR_PALETTE['severity']['critical'], 'textShadow': f"0 0 10px {COLOR_PALETTE['severity']['critical']}"}),
                        html.H3(id='kpi-critical-alerts', className="mb-0", style={'fontWeight': 'bold'}),
                        html.P("Critical Alerts", className="text-muted small mb-0")
                    ], className="text-center")
                ])
            ], style={**GLASS_STYLE, 'borderLeft': f"4px solid {COLOR_PALETTE['severity']['critical']}"}, 
               className="mb-3"),
            md=3, sm=6
        ),
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-server fa-2x mb-2", 
                               style={'color': COLOR_PALETTE['accent_purple'], 'textShadow': f"0 0 10px {COLOR_PALETTE['accent_purple']}"}),
                        html.H3(id='kpi-unique-hosts', className="mb-0", style={'fontWeight': 'bold'}),
                        html.P("Monitored Hosts", className="text-muted small mb-0")
                    ], className="text-center")
                ])
            ], style={**GLASS_STYLE, 'borderLeft': f"4px solid {COLOR_PALETTE['accent_purple']}"}, 
               className="mb-3"),
            md=3, sm=6
        ),
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fas fa-radar fa-2x mb-2", 
                               style={'color': COLOR_PALETTE['severity']['medium'], 'textShadow': f"0 0 10px {COLOR_PALETTE['severity']['medium']}"}),
                        html.H3(id='kpi-avg-score', className="mb-0", style={'fontWeight': 'bold'}),
                        html.P("Avg Threat Score", className="text-muted small mb-0")
                    ], className="text-center")
                ])
            ], style={**GLASS_STYLE, 'borderLeft': f"4px solid {COLOR_PALETTE['severity']['medium']}"}, 
               className="mb-3"),
            md=3, sm=6
        )
    ]),
    
    # Main Content Row 1
    dbc.Row([
        # Threat Trends
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-wave-square me-2"),
                    "Neural Threat Topology"
                ], style={'backgroundColor': 'rgba(0,0,0,0)', 'borderBottom': f"1px solid {COLOR_PALETTE['accent_blue']}", 'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='trend-graph', config={'displayModeBar': False})
                ])
            ], style=GLASS_STYLE, className="mb-3"),
        ], md=8),
        
        # 3D Threat Cluster Visualization
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-cube me-2"),
                    "3D Threat Matrix"
                ], style={'backgroundColor': 'rgba(0,0,0,0)', 'borderBottom': f"1px solid {COLOR_PALETTE['accent_purple']}", 'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='severity-pie', config={'displayModeBar': False}) # Reusing ID for simplicity
                ])
            ], style=GLASS_STYLE, className="mb-3"),
        ], md=4)
    ]),
    
    # Main Content Row 2
    dbc.Row([
        # Attack Types Bar Chart
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-bug me-2"),
                    "Attack Vectors"
                ], style={'backgroundColor': 'rgba(0,0,0,0)', 'borderBottom': f"1px solid {COLOR_PALETTE['accent_cyan']}", 'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='type-graph', config={'displayModeBar': False})
                ])
            ], style=GLASS_STYLE, className="mb-3"),
        ], md=6),
        
        # Process Activity
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-cogs me-2"),
                    "Compromised Processes"
                ], style={'backgroundColor': 'rgba(0,0,0,0)', 'borderBottom': f"1px solid {COLOR_PALETTE['severity']['medium']}", 'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='process-graph', config={'displayModeBar': False})
                ])
            ], style=GLASS_STYLE, className="mb-3"),
        ], md=6)
    ]),
    
    # Main Content Row 3
    dbc.Row([
        # Hourly Heatmap
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-calendar-alt me-2"),
                    "Temporal Heatmap"
                ], style={'backgroundColor': 'rgba(0,0,0,0)', 'borderBottom': f"1px solid {COLOR_PALETTE['accent_purple']}", 'fontWeight': '600'}),
                dbc.CardBody([
                    dcc.Graph(id='heatmap-graph', config={'displayModeBar': False})
                ])
            ], style=GLASS_STYLE, className="mb-3"),
        ], md=8),
        
        # Top Hosts Table
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-network-wired me-2"),
                    "Target Grid"
                ], style={'backgroundColor': 'rgba(0,0,0,0)', 'borderBottom': f"1px solid {COLOR_PALETTE['severity']['high']}", 'fontWeight': '600'}),
                dbc.CardBody([
                    html.Div(id='hosts-table', style={'maxHeight': '400px', 'overflowY': 'auto'})
                ])
            ], style=GLASS_STYLE, className="mb-3"),
        ], md=4)
    ]),
    
    # Latest Alerts Section
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-satellite-dish me-2"),
                    "Live Telemetry Feed"
                ], style={'backgroundColor': 'rgba(0,0,0,0)', 'borderBottom': f"1px solid {COLOR_PALETTE['severity']['critical']}", 'fontWeight': '600'}),
                dbc.CardBody([
                    html.Div(id='alerts-container', style={'maxHeight': '500px', 'overflowY': 'auto'})
                ])
            ], style=GLASS_STYLE, className="mb-3")
        ])
    ]),

    # Hidden interval component for auto-refresh
    dcc.Interval(
        id='interval-component',
        interval=REFRESH_INTERVAL_MS,
        n_intervals=0
    )
], fluid=True, style={
    'backgroundColor': COLOR_PALETTE['background'],
    'backgroundImage': 'radial-gradient(circle at 50% -20%, #151a35, #02050f)',
    'minHeight': '100vh', 
    'padding': '20px'
})

# --- Callbacks ---

# Callback to update KPI cards
@app.callback(
    [Output('kpi-total-alerts', 'children'),
     Output('kpi-critical-alerts', 'children'),
     Output('kpi-unique-hosts', 'children'),
     Output('kpi-avg-score', 'children'),
     Output('ai-analyst-text', 'children'),
     Output('critical-alarm-audio', 'autoPlay')],
    Input('interval-component', 'n_intervals')
)
def update_kpis(n):
    df = load_alerts()
    kpis = calculate_kpis(df)
    
    # Simulated AI Analyst text
    ai_text = "System nominal. Scanning memory regions..."
    play_audio = False
    
    if not df.empty:
        latest = df.iloc[-1]
        if latest['severity'] == 'critical':
            ai_text = f"CRITICAL ANOMALY: Highly evasive {latest['alert_type']} detected on {latest['host']}. Memory entropy exceeds normal thresholds. Process '{latest['process_name']}' [PID {latest['pid']}] automatically quarantined."
            play_audio = True
        elif latest['severity'] == 'high':
            ai_text = f"WARNING: Suspicious {latest['alert_type']} activity via {latest['process_name']}. Analyzing lateral movement probability."
        elif kpis['alerts_last_hour'] > 50:
            ai_text = f"Sustained attack volume detected. {kpis['alerts_last_hour']} incidents logged in the last hour. Recommend firewall restriction."

    return (
        str(kpis['total_alerts']),
        str(kpis['critical_alerts']),
        str(kpis['unique_hosts']),
        str(kpis['avg_threat_score']),
        ai_text,
        play_audio
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
                ], style={**GLASS_STYLE, 
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

# Callback to update severity 3D scatter chart
@app.callback(
    Output('severity-pie', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_3d_scatter(n):
    df = load_alerts()
    if df.empty:
        return create_empty_figure('No active matrix data')
    
    # Create a 3D scatter plot of the last 100 alerts
    df_recent = df.tail(100).copy()
    
    fig = px.scatter_3d(df_recent, 
                        x='hour', 
                        y='threat_score_total', 
                        z='pid',
                        color='severity',
                        size_max=10,
                        hover_name='process_name',
                        color_discrete_map=COLOR_PALETTE['severity'])
    
    fig.update_layout(
        paper_bgcolor=COLOR_PALETTE['graph_bg'],
        plot_bgcolor=COLOR_PALETTE['graph_bg'],
        font_color=COLOR_PALETTE['text_primary'],
        showlegend=False,
        margin=dict(l=0, r=0, t=0, b=0),
        scene=dict(
            xaxis=dict(showgrid=True, gridcolor=COLOR_PALETTE['grid_color'], backgroundcolor='rgba(0,0,0,0)'),
            yaxis=dict(showgrid=True, gridcolor=COLOR_PALETTE['grid_color'], backgroundcolor='rgba(0,0,0,0)'),
            zaxis=dict(showgrid=True, gridcolor=COLOR_PALETTE['grid_color'], backgroundcolor='rgba(0,0,0,0)'),
            bgcolor='rgba(0,0,0,0)'
        ),
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
    app.run_server(host='0.0.0.0', port=8888, debug=False)

# Expose server for Gunicorn
server = app.server

