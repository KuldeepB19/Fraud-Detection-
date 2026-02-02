"""
UPI LOG ANALYZER - STREAMLIT DASHBOARD
Real-Time Fraud Detection System
Date: 02-01-2026
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import random
try:
    from ydata_profiling import ProfileReport
    PROFILING_AVAILABLE = True
except Exception as e:
    PROFILING_AVAILABLE = False

import streamlit.components.v1 as components
import base64
from io import BytesIO
import warnings
warnings.filterwarnings('ignore')

# Page Configuration
st.set_page_config(
    page_title="UPI Log Analyzer Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .alert-critical {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    .alert-warning {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    .alert-success {
        background-color: #e8f5e9;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# HELPER FUNCTIONS FOR DATA GENERATION
# ============================================================================

def generate_timestamps(n, base_date, hours_range=24):
    """Generate random timestamps"""
    timestamps = []
    for i in range(n):
        random_seconds = random.randint(0, hours_range * 3600)
        timestamp = base_date + timedelta(seconds=random_seconds)
        timestamps.append(timestamp.strftime('%Y-%m-%d %H:%M:%S'))
    return timestamps

def generate_ip():
    """Generate random IP address"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

@st.cache_data
def generate_synthetic_data():
    """Generate all 5 synthetic CSV files"""
    
    np.random.seed(42)
    random.seed(42)
    
    base_date = datetime(2026, 2, 1, 0, 0, 0)
    
    # User pools
    user_ids = [f"USR{str(i).zfill(4)}" for i in range(1, 301)]
    suspicious_users = [f"SUS{str(i).zfill(4)}" for i in range(1, 51)]
    
    # IP pools
    normal_ips = [generate_ip() for _ in range(200)]
    suspicious_ips = [generate_ip() for _ in range(30)]
    
    # FILE 1: User Login Logs
    login_data = {
        'timestamp': generate_timestamps(500, base_date),
        'user_id': [],
        'ip_address': [],
        'login_status': [],
        'browser': []
    }
    
    browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera', 'Mobile_App']
    
    for i in range(500):
        if random.random() < 0.85:
            login_data['user_id'].append(random.choice(user_ids))
            login_data['ip_address'].append(random.choice(normal_ips))
            login_data['login_status'].append(np.random.choice(['success', 'failed'], p=[0.95, 0.05]))
        else:
            login_data['user_id'].append(random.choice(suspicious_users))
            login_data['ip_address'].append(random.choice(suspicious_ips))
            login_data['login_status'].append(np.random.choice(['success', 'failed'], p=[0.3, 0.7]))
        
        login_data['browser'].append(random.choice(browsers))
    
    df1_login = pd.DataFrame(login_data).sort_values('timestamp').reset_index(drop=True)
    
    # FILE 2: Session Duration Logs
    session_data = {
        'session_id': [f"SES{str(i).zfill(5)}" for i in range(1, 501)],
        'user_id': [],
        'start_time': [],
        'end_time': [],
        'duration_minutes': []
    }
    
    for i in range(500):
        start = base_date + timedelta(seconds=random.randint(0, 24*3600))
        
        if random.random() < 0.80:
            duration_min = random.randint(5, 60)
            session_data['user_id'].append(random.choice(user_ids))
        else:
            if random.random() < 0.5:
                duration_min = random.randint(1, 3)
            else:
                duration_min = random.randint(180, 480)
            session_data['user_id'].append(random.choice(suspicious_users))
        
        end = start + timedelta(minutes=duration_min)
        
        session_data['start_time'].append(start.strftime('%Y-%m-%d %H:%M:%S'))
        session_data['end_time'].append(end.strftime('%Y-%m-%d %H:%M:%S'))
        session_data['duration_minutes'].append(duration_min)
    
    df2_duration = pd.DataFrame(session_data).sort_values('start_time').reset_index(drop=True)
    
    # FILE 3: Unauthenticated Access
    unauth_data = {
        'timestamp': generate_timestamps(500, base_date),
        'ip_address': [],
        'auth_status': [],
        'attempt_count': [],
        'failure_reason': []
    }
    
    failure_reasons = ['Invalid_Credentials', 'Expired_Token', 'Missing_Auth_Header', 
                       'Brute_Force_Detected', 'Account_Locked', 'Invalid_OTP']
    
    for i in range(500):
        if random.random() < 0.70:
            unauth_data['ip_address'].append(random.choice(normal_ips))
            unauth_data['auth_status'].append('authenticated')
            unauth_data['attempt_count'].append(1)
            unauth_data['failure_reason'].append('None')
        else:
            unauth_data['ip_address'].append(random.choice(suspicious_ips))
            unauth_data['auth_status'].append('unauthenticated')
            unauth_data['attempt_count'].append(random.randint(1, 15))
            unauth_data['failure_reason'].append(random.choice(failure_reasons))
    
    df3_unauth = pd.DataFrame(unauth_data).sort_values('timestamp').reset_index(drop=True)
    
    # FILE 4: Request Logs
    request_data = {
        'timestamp': generate_timestamps(500, base_date),
        'ip_address': [],
        'request_type': [],
        'payload_size': [],
        'status_code': []
    }
    
    for i in range(500):
        rand = random.random()
        if rand < 0.75:
            request_data['ip_address'].append(random.choice(normal_ips))
            request_data['request_type'].append('normal')
            request_data['payload_size'].append(random.randint(100, 5000))
            request_data['status_code'].append(np.random.choice([200, 400], p=[0.95, 0.05]))
        elif rand < 0.90:
            request_data['ip_address'].append(random.choice(suspicious_ips))
            request_data['request_type'].append('blank')
            request_data['payload_size'].append(random.randint(0, 50))
            request_data['status_code'].append(np.random.choice([400, 403], p=[0.6, 0.4]))
        else:
            request_data['ip_address'].append(random.choice(suspicious_ips))
            request_data['request_type'].append('dos_attack')
            request_data['payload_size'].append(random.randint(10000, 50000))
            request_data['status_code'].append(np.random.choice([429, 503], p=[0.7, 0.3]))
    
    df4_requests = pd.DataFrame(request_data).sort_values('timestamp').reset_index(drop=True)
    
    # FILE 5: Service Subscriptions
    service_data = {
        'user_id': [],
        'service_name': [],
        'subscription_date': [],
        'status': [],
        'plan_type': []
    }
    
    services = ['UPI_Transfer', 'Bill_Payment', 'Mobile_Recharge', 'DTH_Recharge', 
                'Money_Request', 'QR_Payment', 'Merchant_Payment', 'International_Transfer']
    plans = ['Basic', 'Premium', 'Gold', 'Enterprise']
    
    for i in range(500):
        if random.random() < 0.85:
            service_data['user_id'].append(random.choice(user_ids))
            service_data['status'].append(np.random.choice(['active', 'inactive'], p=[0.9, 0.1]))
        else:
            service_data['user_id'].append(random.choice(suspicious_users))
            service_data['status'].append(np.random.choice(['active', 'inactive', 'suspended', 'pending'], 
                                                          p=[0.3, 0.2, 0.4, 0.1]))
        
        service_data['service_name'].append(random.choice(services))
        sub_date = base_date - timedelta(days=random.randint(0, 180))
        service_data['subscription_date'].append(sub_date.strftime('%Y-%m-%d'))
        service_data['plan_type'].append(random.choice(plans))
    
    df5_services = pd.DataFrame(service_data).sort_values('subscription_date').reset_index(drop=True)
    
    return df1_login, df2_duration, df3_unauth, df4_requests, df5_services

# ============================================================================
# VISUALIZATION FUNCTIONS
# ============================================================================

def create_login_trend_chart(df):
    """Login success/failure trend over time"""
    df_copy = df.copy()
    df_copy['timestamp'] = pd.to_datetime(df_copy['timestamp'])
    df_copy['hour'] = df_copy['timestamp'].dt.hour
    
    trend = df_copy.groupby(['hour', 'login_status']).size().reset_index(name='count')
    
    fig = px.line(trend, x='hour', y='count', color='login_status',
                  title='Login Attempts by Hour',
                  labels={'hour': 'Hour of Day', 'count': 'Number of Attempts'},
                  color_discrete_map={'success': '#4caf50', 'failed': '#f44336'})
    
    fig.update_layout(hovermode='x unified', height=400)
    return fig

def create_session_distribution(df):
    """Session duration distribution"""
    fig = px.histogram(df, x='duration_minutes', 
                      title='Session Duration Distribution',
                      labels={'duration_minutes': 'Duration (minutes)', 'count': 'Frequency'},
                      nbins=50,
                      color_discrete_sequence=['#1f77b4'])
    
    # Add vertical lines for thresholds
    fig.add_vline(x=3, line_dash="dash", line_color="red", 
                  annotation_text="Suspicious (< 3 min)")
    fig.add_vline(x=180, line_dash="dash", line_color="orange", 
                  annotation_text="Suspicious (> 180 min)")
    
    fig.update_layout(height=400)
    return fig

def create_auth_pie_chart(df):
    """Authentication status breakdown"""
    auth_counts = df['auth_status'].value_counts()
    
    fig = px.pie(values=auth_counts.values, names=auth_counts.index,
                title='Authentication Status Distribution',
                color_discrete_map={'authenticated': '#4caf50', 'unauthenticated': '#f44336'})
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(height=400)
    return fig

def create_request_type_chart(df):
    """Request type breakdown"""
    request_counts = df['request_type'].value_counts()
    
    colors = {'normal': '#4caf50', 'blank': '#ff9800', 'dos_attack': '#f44336'}
    
    fig = px.bar(x=request_counts.index, y=request_counts.values,
                title='Request Type Distribution',
                labels={'x': 'Request Type', 'y': 'Count'},
                color=request_counts.index,
                color_discrete_map=colors)
    
    fig.update_layout(showlegend=False, height=400)
    return fig

def create_top_ips_chart(df, top_n=10):
    """Top attacking IPs"""
    suspicious_df = df[df['request_type'].isin(['blank', 'dos_attack'])]
    top_ips = suspicious_df['ip_address'].value_counts().head(top_n)
    
    fig = px.bar(x=top_ips.values, y=top_ips.index, orientation='h',
                title=f'Top {top_n} Attacking IP Addresses',
                labels={'x': 'Attack Count', 'y': 'IP Address'},
                color=top_ips.values,
                color_continuous_scale='Reds')
    
    fig.update_layout(height=400, showlegend=False)
    return fig

def create_attack_heatmap(df):
    """Attack pattern heatmap by hour"""
    df_copy = df.copy()
    df_copy['timestamp'] = pd.to_datetime(df_copy['timestamp'])
    df_copy['hour'] = df_copy['timestamp'].dt.hour
    df_copy['day'] = df_copy['timestamp'].dt.day_name()
    
    # Filter only attacks
    attacks = df_copy[df_copy['request_type'].isin(['blank', 'dos_attack'])]
    
    heatmap_data = attacks.groupby(['day', 'hour']).size().reset_index(name='count')
    heatmap_pivot = heatmap_data.pivot(index='day', columns='hour', values='count').fillna(0)
    
    fig = px.imshow(heatmap_pivot,
                   labels=dict(x="Hour of Day", y="Day of Week", color="Attack Count"),
                   title="Attack Pattern Heatmap",
                   color_continuous_scale='Reds',
                   aspect="auto")
    
    fig.update_layout(height=400)
    return fig

def create_service_chart(df):
    """Service subscription breakdown"""
    service_counts = df['service_name'].value_counts()
    
    fig = px.bar(x=service_counts.index, y=service_counts.values,
                title='Service Subscription Distribution',
                labels={'x': 'Service Name', 'y': 'Count'},
                color=service_counts.values,
                color_continuous_scale='Blues')
    
    fig.update_layout(xaxis_tickangle=-45, height=400, showlegend=False)
    return fig

def create_fraud_score_gauge(login_df, unauth_df, request_df):
    """Calculate and display fraud risk score"""
    
    # Calculate metrics
    failed_login_rate = len(login_df[login_df['login_status']=='failed']) / len(login_df) * 100
    unauth_rate = len(unauth_df[unauth_df['auth_status']=='unauthenticated']) / len(unauth_df) * 100
    attack_rate = len(request_df[request_df['request_type'].isin(['blank', 'dos_attack'])]) / len(request_df) * 100
    
    # Calculate composite fraud score (0-100)
    fraud_score = (failed_login_rate * 0.3 + unauth_rate * 0.4 + attack_rate * 0.3)
    
    # Determine risk level
    if fraud_score < 15:
        risk_level = "LOW"
        color = "green"
    elif fraud_score < 30:
        risk_level = "MEDIUM"
        color = "yellow"
    elif fraud_score < 50:
        risk_level = "HIGH"
        color = "orange"
    else:
        risk_level = "CRITICAL"
        color = "red"
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = fraud_score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': f"Fraud Risk Score<br><span style='font-size:0.8em;color:{color}'>Risk Level: {risk_level}</span>"},
        delta = {'reference': 20},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 15], 'color': "lightgreen"},
                {'range': [15, 30], 'color': "lightyellow"},
                {'range': [30, 50], 'color': "orange"},
                {'range': [50, 100], 'color': "lightcoral"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 50
            }
        }
    ))
    
    fig.update_layout(height=400)
    return fig, fraud_score, risk_level

# ============================================================================
# MAIN APP
# ============================================================================

def main():
    # Header
    st.markdown('<p class="main-header">🔒 UPI Log Analyzer Dashboard</p>', unsafe_allow_html=True)
    st.markdown("### Real-Time Fraud Detection & Analysis System")
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=100)
        st.title("⚙️ Configuration")
        
        # Data Source Selection
        data_source = st.radio(
            "Select Data Source:",
            ["📤 Upload CSV Files", "🔄 Generate Synthetic Data"]
        )
        
        st.markdown("---")
        
        # File type selection for upload
        if data_source == "📤 Upload CSV Files":
            st.info("Upload your log files below")
            uploaded_login = st.file_uploader("1️⃣ User Login Logs", type=['csv'], key='login')
            uploaded_duration = st.file_uploader("2️⃣ Session Duration Logs", type=['csv'], key='duration')
            uploaded_unauth = st.file_uploader("3️⃣ Unauth Access Logs", type=['csv'], key='unauth')
            uploaded_request = st.file_uploader("4️⃣ Request Logs", type=['csv'], key='request')
            uploaded_service = st.file_uploader("5️⃣ Service Subscription Logs", type=['csv'], key='service')
            
            analyze_button = st.button("🔍 Analyze Uploaded Data", type="primary")
        else:
            st.info("Click below to generate synthetic data")
            analyze_button = st.button("🔄 Generate & Analyze", type="primary")
        
        st.markdown("---")
        st.markdown("### 📊 Features")
        st.markdown("""
        - Fraud Risk Scoring
        - Interactive Visualizations
        - Pandas Profiling Reports
        - Data Export Options
        - Anomaly Detection
        """)
    
    # Main Content
    if analyze_button:
        with st.spinner("Processing data..."):
            
            # Load or generate data
            if data_source == "📤 Upload CSV Files":
                if all([uploaded_login, uploaded_duration, uploaded_unauth, uploaded_request, uploaded_service]):
                    df1_login = pd.read_csv(uploaded_login)
                    df2_duration = pd.read_csv(uploaded_duration)
                    df3_unauth = pd.read_csv(uploaded_unauth)
                    df4_requests = pd.read_csv(uploaded_request)
                    df5_services = pd.read_csv(uploaded_service)
                    st.success("✅ All files uploaded successfully!")
                else:
                    st.error("❌ Please upload all 5 CSV files to proceed!")
                    return
            else:
                df1_login, df2_duration, df3_unauth, df4_requests, df5_services = generate_synthetic_data()
                st.success("✅ Synthetic data generated successfully!")
            
            # Store in session state
            st.session_state['df1_login'] = df1_login
            st.session_state['df2_duration'] = df2_duration
            st.session_state['df3_unauth'] = df3_unauth
            st.session_state['df4_requests'] = df4_requests
            st.session_state['df5_services'] = df5_services
            st.session_state['data_loaded'] = True
    
    # Display dashboard if data is loaded
    if st.session_state.get('data_loaded', False):
        
        df1_login = st.session_state['df1_login']
        df2_duration = st.session_state['df2_duration']
        df3_unauth = st.session_state['df3_unauth']
        df4_requests = st.session_state['df4_requests']
        df5_services = st.session_state['df5_services']
        
        # Tabs for different sections
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Dashboard Overview", 
            "📈 Detailed Analysis", 
            "🔍 Pandas Profiling",
            "📥 Data Export",
            "⚠️ Anomaly Detection"
        ])
        
        # ===== TAB 1: Dashboard Overview =====
        with tab1:
            st.header("📊 Executive Dashboard")
            
            # Fraud Risk Score
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                fraud_fig, fraud_score, risk_level = create_fraud_score_gauge(df1_login, df3_unauth, df4_requests)
                st.plotly_chart(fraud_fig, use_container_width=True)
            
            with col2:
                st.metric("Total Login Attempts", len(df1_login))
                st.metric("Failed Logins", len(df1_login[df1_login['login_status']=='failed']))
                st.metric("Unique Users", df1_login['user_id'].nunique())
            
            with col3:
                st.metric("DOS Attacks", len(df4_requests[df4_requests['request_type']=='dos_attack']))
                st.metric("Blank Requests", len(df4_requests[df4_requests['request_type']=='blank']))
                st.metric("Unauth Attempts", len(df3_unauth[df3_unauth['auth_status']=='unauthenticated']))
            
            st.markdown("---")
            
            # Key Metrics Cards
            st.subheader("🎯 Key Security Metrics")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                failed_rate = len(df1_login[df1_login['login_status']=='failed']) / len(df1_login) * 100
                st.markdown(f"""
                <div class="{'alert-critical' if failed_rate > 10 else 'alert-success'}">
                    <h4>Login Failure Rate</h4>
                    <h2>{failed_rate:.1f}%</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                avg_duration = df2_duration['duration_minutes'].mean()
                st.markdown(f"""
                <div class="alert-success">
                    <h4>Avg Session Duration</h4>
                    <h2>{avg_duration:.1f} min</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                unauth_rate = len(df3_unauth[df3_unauth['auth_status']=='unauthenticated']) / len(df3_unauth) * 100
                st.markdown(f"""
                <div class="{'alert-critical' if unauth_rate > 30 else 'alert-warning'}">
                    <h4>Unauth Rate</h4>
                    <h2>{unauth_rate:.1f}%</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col4:
                attack_count = len(df4_requests[df4_requests['request_type'].isin(['blank', 'dos_attack'])])
                st.markdown(f"""
                <div class="{'alert-critical' if attack_count > 100 else 'alert-warning'}">
                    <h4>Total Attacks</h4>
                    <h2>{attack_count}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Quick Visualizations
            col1, col2 = st.columns(2)
            
            with col1:
                st.plotly_chart(create_login_trend_chart(df1_login), use_container_width=True)
                st.plotly_chart(create_auth_pie_chart(df3_unauth), use_container_width=True)
            
            with col2:
                st.plotly_chart(create_request_type_chart(df4_requests), use_container_width=True)
                st.plotly_chart(create_session_distribution(df2_duration), use_container_width=True)
        
        # ===== TAB 2: Detailed Analysis =====
        with tab2:
            st.header("📈 Detailed Analysis & Visualizations")
            
            analysis_type = st.selectbox(
                "Select Analysis Type:",
                ["Login Analysis", "Session Analysis", "Authentication Analysis", 
                 "Attack Analysis", "Service Analysis"]
            )
            
            if analysis_type == "Login Analysis":
                st.subheader("🔐 Login Analysis")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.plotly_chart(create_login_trend_chart(df1_login), use_container_width=True)
                
                with col2:
                    # Browser distribution
                    browser_counts = df1_login['browser'].value_counts()
                    fig = px.pie(values=browser_counts.values, names=browser_counts.index,
                                title='Browser Distribution')
                    st.plotly_chart(fig, use_container_width=True)
                
                st.subheader("📋 Recent Failed Logins")
                failed_logins = df1_login[df1_login['login_status']=='failed'].tail(10)
                st.dataframe(failed_logins, use_container_width=True)
            
            elif analysis_type == "Session Analysis":
                st.subheader("⏱️ Session Duration Analysis")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.plotly_chart(create_session_distribution(df2_duration), use_container_width=True)
                
                with col2:
                    # Suspicious sessions
                    suspicious = df2_duration[
                        (df2_duration['duration_minutes'] < 3) | 
                        (df2_duration['duration_minutes'] > 180)
                    ]
                    
                    st.metric("Suspicious Sessions", len(suspicious))
                    st.metric("Very Short (<3 min)", len(df2_duration[df2_duration['duration_minutes'] < 3]))
                    st.metric("Very Long (>180 min)", len(df2_duration[df2_duration['duration_minutes'] > 180]))
                
                st.subheader("⚠️ Suspicious Sessions")
                st.dataframe(suspicious.head(10), use_container_width=True)
            
            elif analysis_type == "Authentication Analysis":
                st.subheader("🔓 Authentication Analysis")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.plotly_chart(create_auth_pie_chart(df3_unauth), use_container_width=True)
                
                with col2:
                    # Failure reasons
                    failure_df = df3_unauth[df3_unauth['auth_status']=='unauthenticated']
                    reason_counts = failure_df['failure_reason'].value_counts()
                    
                    fig = px.bar(x=reason_counts.index, y=reason_counts.values,
                                title='Authentication Failure Reasons',
                                labels={'x': 'Reason', 'y': 'Count'})
                    fig.update_layout(xaxis_tickangle=-45)
                    st.plotly_chart(fig, use_container_width=True)
                
                st.subheader("🚨 High-Risk IPs (Multiple Failed Attempts)")
                high_risk = df3_unauth[df3_unauth['attempt_count'] > 5].sort_values('attempt_count', ascending=False)
                st.dataframe(high_risk.head(10), use_container_width=True)
            
            elif analysis_type == "Attack Analysis":
                st.subheader("⚔️ Attack Pattern Analysis")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.plotly_chart(create_request_type_chart(df4_requests), use_container_width=True)
                
                with col2:
                    st.plotly_chart(create_top_ips_chart(df4_requests, 10), use_container_width=True)
                
                st.plotly_chart(create_attack_heatmap(df4_requests), use_container_width=True)
                
                st.subheader("🎯 Recent Attack Logs")
                attacks = df4_requests[df4_requests['request_type'].isin(['blank', 'dos_attack'])].tail(10)
                st.dataframe(attacks, use_container_width=True)
            
            elif analysis_type == "Service Analysis":
                st.subheader("💳 Service Subscription Analysis")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.plotly_chart(create_service_chart(df5_services), use_container_width=True)
                
                with col2:
                    # Status distribution
                    status_counts = df5_services['status'].value_counts()
                    fig = px.pie(values=status_counts.values, names=status_counts.index,
                                title='Subscription Status Distribution')
                    st.plotly_chart(fig, use_container_width=True)
                
                st.subheader("🔴 Suspended/Inactive Services")
                suspended = df5_services[df5_services['status'].isin(['suspended', 'inactive'])]
                st.dataframe(suspended.head(10), use_container_width=True)
        
        # ===== TAB 3: Pandas Profiling =====
        with tab3:
            st.header("🔍 Pandas Profiling Reports")
            st.info("Generate comprehensive HTML reports for each dataset")
            
            report_type = st.selectbox(
                "Select Report to Generate:",
                ["User Login Logs", "Session Duration Logs", "Unauth Access Logs", 
                 "Request Logs", "Service Subscription Logs"]
            )
            
            if st.button("📊 Generate Pandas Profile Report"):
                with st.spinner(f"Generating profile report for {report_type}..."):
                    
                    # Select appropriate dataframe
                    if report_type == "User Login Logs":
                        df_selected = df1_login
                        title = "User Login Analysis Report"
                    elif report_type == "Session Duration Logs":
                        df_selected = df2_duration
                        title = "Session Duration Analysis Report"
                    elif report_type == "Unauth Access Logs":
                        df_selected = df3_unauth
                        title = "Unauthenticated Access Analysis Report"
                    elif report_type == "Request Logs":
                        df_selected = df4_requests
                        title = "Request & DOS Attack Analysis Report"
                    else:
                        df_selected = df5_services
                        title = "Service Subscription Analysis Report"
                    
                    # Generate profile
                    profile = ProfileReport(df_selected, title=title, explorative=True)
                    
                    # Export to HTML
                    profile_html = profile.to_html()
                    
                    # Display in iframe
                    st.success("✅ Report generated successfully!")
                    components.html(profile_html, height=800, scrolling=True)
                    
                    # Download button
                    st.download_button(
                        label="📥 Download HTML Report",
                        data=profile_html,
                        file_name=f"{report_type.lower().replace(' ', '_')}_profile.html",
                        mime="text/html"
                    )
        
        # ===== TAB 4: Data Export =====
        with tab4:
            st.header("📥 Data Export Options")
            
            st.subheader("Download Generated CSV Files")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.download_button(
                    "📄 Download Login Logs CSV",
                    df1_login.to_csv(index=False),
                    "user_login_logs.csv",
                    "text/csv"
                )
                
                st.download_button(
                    "📄 Download Session Logs CSV",
                    df2_duration.to_csv(index=False),
                    "session_duration_logs.csv",
                    "text/csv"
                )
                
                st.download_button(
                    "📄 Download Unauth Logs CSV",
                    df3_unauth.to_csv(index=False),
                    "unauth_access_logs.csv",
                    "text/csv"
                )
            
            with col2:
                st.download_button(
                    "📄 Download Request Logs CSV",
                    df4_requests.to_csv(index=False),
                    "request_logs.csv",
                    "text/csv"
                )
                
                st.download_button(
                    "📄 Download Service Logs CSV",
                    df5_services.to_csv(index=False),
                    "service_subscription_logs.csv",
                    "text/csv"
                )
            
            st.markdown("---")
            
            st.subheader("📊 Export Summary Report")
            
            if st.button("Generate Summary Report"):
                summary = f"""
UPI LOG ANALYZER - SUMMARY REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

1. LOGIN ANALYSIS:
   - Total Logins: {len(df1_login)}
   - Successful: {len(df1_login[df1_login['login_status']=='success'])}
   - Failed: {len(df1_login[df1_login['login_status']=='failed'])}
   - Unique Users: {df1_login['user_id'].nunique()}

2. SESSION ANALYSIS:
   - Total Sessions: {len(df2_duration)}
   - Average Duration: {df2_duration['duration_minutes'].mean():.2f} minutes
   - Suspicious Short (<3 min): {len(df2_duration[df2_duration['duration_minutes']<3])}
   - Suspicious Long (>180 min): {len(df2_duration[df2_duration['duration_minutes']>180])}

3. AUTHENTICATION ANALYSIS:
   - Total Attempts: {len(df3_unauth)}
   - Authenticated: {len(df3_unauth[df3_unauth['auth_status']=='authenticated'])}
   - Unauthenticated: {len(df3_unauth[df3_unauth['auth_status']=='unauthenticated'])}

4. ATTACK ANALYSIS:
   - Total Requests: {len(df4_requests)}
   - Normal: {len(df4_requests[df4_requests['request_type']=='normal'])}
   - Blank Requests: {len(df4_requests[df4_requests['request_type']=='blank'])}
   - DOS Attacks: {len(df4_requests[df4_requests['request_type']=='dos_attack'])}

5. SERVICE ANALYSIS:
   - Total Subscriptions: {len(df5_services)}
   - Active: {len(df5_services[df5_services['status']=='active'])}
   - Suspended: {len(df5_services[df5_services['status']=='suspended'])}

FRAUD RISK SCORE: {fraud_score:.2f}/100
RISK LEVEL: {risk_level}
{'='*60}
                """
                
                st.text_area("Summary Report", summary, height=400)
                
                st.download_button(
                    "📥 Download Summary Report",
                    summary,
                    "summary_report.txt",
                    "text/plain"
                )
        
        # ===== TAB 5: Anomaly Detection =====
        with tab5:
            st.header("⚠️ Anomaly Detection")
            
            st.subheader("🚨 Detected Anomalies")
            
            # Failed Login Anomalies
            with st.expander("🔴 Critical: Failed Login Patterns"):
                failed_by_ip = df1_login[df1_login['login_status']=='failed'].groupby('ip_address').size()
                critical_ips = failed_by_ip[failed_by_ip > 5].sort_values(ascending=False)
                
                if len(critical_ips) > 0:
                    st.warning(f"Found {len(critical_ips)} IPs with >5 failed login attempts")
                    st.dataframe(critical_ips.reset_index().rename(columns={0: 'Failed Attempts'}))
                else:
                    st.success("No critical failed login patterns detected")
            
            # Session Duration Anomalies
            with st.expander("🟡 Warning: Suspicious Session Durations"):
                suspicious_sessions = df2_duration[
                    (df2_duration['duration_minutes'] < 3) | 
                    (df2_duration['duration_minutes'] > 180)
                ]
                
                if len(suspicious_sessions) > 0:
                    st.warning(f"Found {len(suspicious_sessions)} suspicious sessions")
                    st.dataframe(suspicious_sessions.head(10))
                else:
                    st.success("No suspicious session durations detected")
            
            # Brute Force Detection
            with st.expander("🔴 Critical: Brute Force Attempts"):
                brute_force = df3_unauth[
                    (df3_unauth['auth_status']=='unauthenticated') & 
                    (df3_unauth['attempt_count'] > 10)
                ]
                
                if len(brute_force) > 0:
                    st.error(f"⚠️ Detected {len(brute_force)} potential brute force attacks!")
                    st.dataframe(brute_force)
                else:
                    st.success("No brute force patterns detected")
            
            # DOS Attack Alerts
            with st.expander("🔴 Critical: DOS Attack Patterns"):
                dos_attacks = df4_requests[df4_requests['request_type']=='dos_attack']
                
                if len(dos_attacks) > 0:
                    st.error(f"⚠️ Detected {len(dos_attacks)} DOS attacks!")
                    
                    dos_by_ip = dos_attacks.groupby('ip_address').size().sort_values(ascending=False).head(10)
                    st.dataframe(dos_by_ip.reset_index().rename(columns={0: 'Attack Count'}))
                else:
                    st.success("No DOS attacks detected")
            
            # Suspended Services
            with st.expander("🟡 Warning: Suspended Services"):
                suspended_services = df5_services[df5_services['status']=='suspended']
                
                if len(suspended_services) > 0:
                    st.warning(f"Found {len(suspended_services)} suspended services")
                    st.dataframe(suspended_services.head(10))
                else:
                    st.success("No suspended services found")
    
    else:
        # Welcome Screen
        st.info("👈 Please select a data source from the sidebar and click the analysis button to begin")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            ### 📊 Dashboard Features
            - Real-time fraud scoring
            - Interactive visualizations
            - Comprehensive metrics
            """)
        
        with col2:
            st.markdown("""
            ### 🔍 Analysis Tools
            - Pandas profiling reports
            - Anomaly detection
            - Pattern recognition
            """)
        
        with col3:
            st.markdown("""
            ### 📥 Export Options
            - Download CSV files
            - Generate reports
            - Summary statistics
            """)

if __name__ == "__main__":
    main()
