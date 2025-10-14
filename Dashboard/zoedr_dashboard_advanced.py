#!/usr/bin/env python3
# zoedr_dashboard_advanced.py - ZoEDR Advanced Dashboard with Live Graphs

import json
import os
import pandas as pd
from datetime import datetime
import time # For sleep in debug
from dash import Dash, html, dcc
import plotly.express as px
from dash.dependencies import Input, Output
import dash_bootstrap_components as dbc

# --- Configuration ---
ALERT_FILE = "/var/log/zoedr/alerts.json" # Consistent with zoedr_common.h
REFRESH_INTERVAL_MS = 5000 # Refresh every 5 seconds
MAX_ALERTS_DISPLAY = 50 # Number of latest alerts to show in the list

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
    return df

# --- Initialize Dash App ---
# Using a Bootstrap theme for a professional look
app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
app.title = "ZoEDR Threat Dashboard - Zeta Realm Security"

# --- Layout Definition ---
app.layout = dbc.Container([
    dbc.Row(dbc.Col(html.H1("🐉 ZoEDR Threat Dashboard - Alpha's Realm", className="text-center text-danger my-4"))),
    
    dbc.Row([
        # Current Alerts Column
        dbc.Col([
            dbc.Card(
                dbc.CardBody([
                    html.H4("🚨 Latest Alerts", className="card-title text-warning"),
                    html.Div(id='alerts-container', style={'maxHeight': '600px', 'overflowY': 'auto'})
                ]),
                className="bg-dark text-light mb-4"
            )
        ], md=6),

        # Graphs Column
        dbc.Col([
            dbc.Card(
                dbc.CardBody([
                    html.H4("📈 Threat Trends Over Time", className="card-title text-info"),
                    dcc.Graph(id='trend-graph', config={'displayModeBar': False})
                ]),
                className="bg-dark text-light mb-4"
            ),
            dbc.Card(
                dbc.CardBody([
                    html.H4("📊 Top Attack Types", className="card-title text-info"),
                    dcc.Graph(id='type-graph', config={'displayModeBar': False})
                ]),
                className="bg-dark text-light mb-4"
            )
        ], md=6)
    ]),

    # Hidden interval component for auto-refresh
    dcc.Interval(
        id='interval-component',
        interval=REFRESH_INTERVAL_MS,
        n_intervals=0
    )
], fluid=True, className="bg-primary text-light") # Using a dark background for the whole container

# --- Callbacks ---

# Callback to update the list of latest alerts
@app.callback(
    Output('alerts-container', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_alerts_list(n):
    df = load_alerts()
    alerts_html = []
    
    # Define severity colors
    severity_colors = {
        'info': '#00BFFF',    # Deep Sky Blue
        'low': '#32CD32',     # Lime Green
        'medium': '#FFD700',  # Gold
        'high': '#FF4500',    # Orange Red
        'critical': '#DC143C' # Crimson
    }

    if not df.empty:
        # Get the latest MAX_ALERTS_DISPLAY alerts
        latest_alerts = df.tail(MAX_ALERTS_DISPLAY).to_dict('records')
        
        for alert in reversed(latest_alerts): # Display latest first
            alerts_html.append(
                dbc.Card(
                    dbc.CardBody([
                        html.H5(f"[{alert['timestamp']}] {alert['alert_type']}", className="card-title",
                                style={'color': severity_colors.get(alert['severity'], '#FFFFFF')}),
                        html.P(f"Host: {alert['host']} | PID: {alert['pid']} | Process: {alert['process_name']}", className="card-text small"),
                        html.P(f"Severity: {alert['severity'].upper()} | Score: {alert['threat_score_total']}", className="card-text small"),
                        html.P(f"Details: {alert['details']}", className="card-text small")
                    ]),
                    className="bg-secondary text-light mb-2", # Use secondary for alert cards
                    style={'borderLeft': f'5px solid {severity_colors.get(alert["severity"], "#888")}'}
                )
            )
    else:
        alerts_html.append(html.P("No alerts yet. System is clean (or not running)."))
    
    return alerts_html

# Callback to update the Threat Trends graph
@app.callback(
    Output('trend-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_trend_graph(n):
    df = load_alerts()
    if df.empty:
        # Return an empty graph with a message
        return {
            'layout': {
                'title': {'text': 'No Data for Threat Trends', 'font': {'color': '#f0f0f0'}},
                'paper_bgcolor': '#121212',
                'plot_bgcolor': '#121212',
                'font': {'color': '#f0f0f0'}
            }
        }
    
    # Group by 1-minute intervals and severity
    df_grouped = df.groupby([pd.Grouper(key='timestamp_dt', freq='1T'), 'severity']).size().reset_index(name='count')
    
    # Order severities for consistent legend and color mapping
    severity_order = ['info', 'low', 'medium', 'high', 'critical']
    df_grouped['severity'] = pd.Categorical(df_grouped['severity'], categories=severity_order, ordered=True)
    df_grouped = df_grouped.sort_values('severity')

    fig = px.line(df_grouped, x='timestamp_dt', y='count', color='severity', title='Threat Trends Over Time',
                  labels={'timestamp_dt': 'Time', 'count': 'Number of Alerts'},
                  color_discrete_map={
                      'info': '#00BFFF',
                      'low': '#32CD32',
                      'medium': '#FFD700',
                      'high': '#FF4500',
                      'critical': '#DC143C'
                  })
    fig.update_layout(
        paper_bgcolor='#1a1a1a', # Darker background for graph paper
        plot_bgcolor='#1a1a1a',  # Darker background for plot area
        font_color='#f0f0f0',
        title_font_color='#f0f0f0',
        xaxis_title_font_color='#f0f0f0',
        yaxis_title_font_color='#f0f0f0',
        legend_title_font_color='#f0f0f0'
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
        # Return an empty graph with a message
        return {
            'layout': {
                'title': {'text': 'No Data for Top Attack Types', 'font': {'color': '#f0f0f0'}},
                'paper_bgcolor': '#121212',
                'plot_bgcolor': '#121212',
                'font': {'color': '#f0f0f0'}
            }
        }

    df_type = df['alert_type'].value_counts().reset_index()
    df_type.columns = ['alert_type', 'count']
    
    fig = px.bar(df_type, x='alert_type', y='count', title='Top Attack Types',
                 labels={'alert_type': 'Attack Type', 'count': 'Number of Alerts'},
                 color='count', # Color bars based on count
                 color_continuous_scale=px.colors.sequential.Plasma) # A nice sequential color scale
    
    fig.update_layout(
        paper_bgcolor='#1a1a1a',
        plot_bgcolor='#1a1a1a',
        font_color='#f0f0f0',
        title_font_color='#f0f0f0',
        xaxis_title_font_color='#f0f0f0',
        yaxis_title_font_color='#f0f0f0',
        coloraxis_colorbar_title_text='Count' # Title for colorbar
    )
    return fig


# --- Run the App ---
if __name__ == '__main__':
    # For development, you might want debug=True
    # For production, ensure debug=False and use a WSGI server like Gunicorn
    app.run_server(host='0.0.0.0', port=8888, debug=False)
