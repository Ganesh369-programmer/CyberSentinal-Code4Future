import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx

# --- PAGE CONFIG ---
st.set_page_config(page_title="Cyber Attack Dashboard", layout="wide")
st.title("🛡️ Phase 4: Attack Visualization Dashboard")

# --- STEP 1: INPUT DATA (Your 'Failed to Connect' Logs) ---
# In a real project, you'd upload a file. Here is a sample based on your request.
raw_logs = [
    {"attacker": "192.168.1.50", "target": "Web_Server", "status": "Failed"},
    {"attacker": "192.168.1.50", "target": "Web_Server", "status": "Failed"},
    {"attacker": "10.0.0.5", "target": "DB_Server", "status": "Failed"},
    {"attacker": "192.168.1.50", "target": "Mail_Server", "status": "Failed"},
    {"attacker": "172.16.0.10", "target": "Web_Server", "status": "Failed"},
    {"attacker": "192.168.1.50", "target": "Web_Server", "status": "Failed"},
]

df = pd.DataFrame(raw_logs)

# --- STEP 2: PLOTLY BAR CHART (Top Attackers) ---
st.subheader("📊 Top Attackers (Failed Attempts)")
# Count failures per IP
attacker_counts = df['attacker'].value_counts().reset_index()
attacker_counts.columns = ['IP Address', 'Failure Count']

fig_bar = px.bar(attacker_counts, x='IP Address', y='Failure Count', 
             color='Failure Count', color_continuous_scale='Reds',
             text_auto=True)
st.plotly_chart(fig_bar, use_container_width=True)

# --- STEP 3: NETWORKX GRAPH (Attacker -> Server Map) ---
st.subheader("🌐 Attack Propagation Map")

# Create the Graph logic
G = nx.Graph()
for _, row in df.iterrows():
    G.add_edge(row['attacker'], row['target'])

# Get positions for the dots (Spring layout makes it look clean)
pos = nx.spring_layout(G)

# Create the Plotly edges (lines)
edge_x = []
edge_y = []
for edge in G.edges():
    x0, y0 = pos[edge[0]]
    x1, y1 = pos[edge[1]]
    edge_x.extend([x0, x1, None])
    edge_y.extend([y0, y1, None])

edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1, color='#888'), hoverinfo='none', mode='lines')

# Create the Plotly nodes (dots)
node_x = []
node_y = []
node_text = []
for node in G.nodes():
    x, y = pos[node]
    node_x.append(x)
    node_y.append(y)
    node_text.append(node)

node_trace = go.Scatter(x=node_x, y=node_y, mode='markers+text', 
                       text=node_text, textposition="top center",
                       marker=dict(size=15, color='red', line_width=2))

# Combine and show
fig_map = go.Figure(data=[edge_trace, node_trace],
                 layout=go.Layout(showlegend=False, margin=dict(b=0,l=0,r=0,t=0),
                 xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                 yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)))

st.plotly_chart(fig_map, use_container_width=True)

st.success("✅ Dashboard loaded successfully. One IP is clearly targeting multiple servers!")