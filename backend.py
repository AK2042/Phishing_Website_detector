from fastapi import FastAPI, HTTPException
from pydantic import BaseModel,EmailStr
import pickle
from feature_extractor import extract_url_features
import requests
from bs4 import BeautifulSoup
import networkx as nx
import matplotlib.pyplot as plt
from urllib.parse import urljoin, urlparse
import pandas as pd
import os
import uuid
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
from urllib.parse import quote_plus
import shutil
import gradio as gr

with open("phishing_detector.pkl", "rb") as f:
    model = pickle.load(f)

FEATURE_NAMES = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", "PrefixSuffix-", "SubDomains",
    "HTTPS", "DomainRegLen", "Favicon", "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding",
    "StatusBarCust", "DisableRightClick", "UsingPopupWindow", "IframeRedirection", "AgeofDomain",
    "DNSRecording", "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport"
]


def predict_url(data):
    try:
        root_features = extract_url_features(data)
        print(f"Root URL features: {root_features}")
        print(type(root_features), len(root_features))
        df_features = pd.DataFrame([root_features], columns=FEATURE_NAMES)
        print("DataFrame shape:", df_features.shape) 
        print("df_features type:", type(df_features))
        print("df_features values ndim:", df_features.values.ndim)
        root_prediction = model.predict(df_features)
        root_label = "Legitimate" if root_prediction == 1 else "Phishing"

        response = requests.get(data, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        links = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(data, href)
            if urlparse(full_url).scheme in ("http", "https"):
                links.add(full_url)

        link_predictions = {}
        for link in links:
            try:
                features = extract_url_features(link)
                df_f=pd.DataFrame([features], columns=FEATURE_NAMES)
                pred = model.predict(df_f)
                link_predictions[link] = "Legitimate" if pred == 1 else "Phishing"
            except Exception:
                link_predictions[link] = "Error"

        G = nx.DiGraph()
        G.add_node(data, label=root_label)

        for link, label in link_predictions.items():
            G.add_node(link, label=label)
            G.add_edge(data, link)

        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G, k=0.5)

        color_map = []
        for node in G.nodes:
            lbl = G.nodes[node].get('label', 'Error')
            if lbl == "Phishing":
                color_map.append("red")
            elif lbl == "Legitimate":
                color_map.append("green")
            else:
                color_map.append("grey")

        nx.draw_networkx_nodes(G, pos, node_color=color_map, node_size=500, alpha=0.8)
        nx.draw_networkx_edges(G, pos, arrows=True)
        nx.draw_networkx_labels(G, pos, font_size=8, font_color="black")

        plt.title("URL Link Graph with Phishing Detection (Green=Legitimate, Red=Phishing)")
        plt.axis("off")

        filename = f"graph_{uuid.uuid4().hex}.png"
        filepath = os.path.join("graphs", filename)
        os.makedirs("graphs", exist_ok=True)
        plt.savefig(filepath)
        plt.close()

        return filepath

    except Exception as e:
        print("Error:", e)
        return None


def gradio_interface(url):
    image_path = predict_url(url)
    return image_path if image_path else "Error generating image."

gr.Interface(
    fn=gradio_interface,
    inputs=gr.Textbox(label="Enter a URL"),
    outputs=gr.Image(type="filepath", label="Phishing Graph"),
    title="Phishing Detector (URL to Image)",
    description="This app predicts phishing links from a URL and displays them as a graph."
).launch()
