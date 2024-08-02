import numpy as np
from scipy.optimize import minimize
import folium
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans, DBSCAN
from sklearn.decomposition import PCA
import json
from datetime import datetime
import os
import time
import subprocess
import asyncio
import tkinter as tk
from tkinter import messagebox
from geopy.distance import great_circle
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sklearn.preprocessing import StandardScaler
from scapy.all import sniff, Dot11, RadioTap

# פונקציה להמרת RSSI למרחק
def rssi_to_distance(rssi, tx_power=-59):
    if rssi == 0:
        return -1.0
    ratio = rssi * 1.0 / tx_power
    if ratio < 1.0:
        return pow(ratio, 10)
    else:
        accuracy = 0.89976 * pow(ratio, 7.7095) + 0.111
        return accuracy

# פונקציה לחישוב מיקום התוקף בעזרת trilateration
def trilaterate(positions, distances):
    def objective_function(estimate):
        return sum((great_circle(estimate, pos).meters - dist)**2 
                   for pos, dist in zip(positions, distances))
    
    initial_guess = np.mean(positions, axis=0)
    result = minimize(objective_function, initial_guess, method='L-BFGS-B')
    return result.x

# פונקציה לאיסוף נתוני RSSI מכרטיסי רשת
async def collect_rssi_data(interface_list):
    rssi_data = {}
    async def collect_from_interface(iface):
        cmd = f"iwconfig {iface} | grep 'Signal level'"
        try:
            output = subprocess.check_output(cmd, shell=True).decode()
            rssi_values = [int(line.split()[-1].replace('dBm', '')) for line in output.split('\n') if 'Signal level' in line]
            rssi_data[iface] = rssi_values
        except subprocess.CalledProcessError:
            rssi_data[iface] = []

    tasks = [asyncio.create_task(collect_from_interface(iface)) for iface in interface_list]
    await asyncio.gather(*tasks)
    return rssi_data

# פונקציה להצגת המיקום על מפה
def display_map(positions, attacker_position):
    mymap = folium.Map(location=[np.mean([pos[0] for pos in positions]), np.mean([pos[1] for pos in positions])], zoom_start=15)
    for pos in positions:
        folium.Marker(location=pos, popup="TP-Link", icon=folium.Icon(color='blue')).add_to(mymap)
    folium.Marker(location=attacker_position, popup="Attacker Position", icon=folium.Icon(color='red')).add_to(mymap)
    mymap.save("wifi_attack_map.html")

# פונקציה לניתוח מתקפות באמצעות Isolation Forest, KMeans, DBSCAN, PCA
def analyze_rssi(rssi_values):
    X = np.array([[rssi] for rssi in rssi_values])
    
    # Standardizing the data
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Isolation Forest
    iso_model = IsolationForest()
    iso_model.fit(X_scaled)
    iso_pred = iso_model.predict(X_scaled)
    iso_outliers = np.where(iso_pred == -1)
    
    # KMeans
    kmeans = KMeans(n_clusters=2)
    kmeans.fit(X_scaled)
    kmeans_pred = kmeans.predict(X_scaled)
    kmeans_outliers = np.where(kmeans_pred == 1)
    
    # DBSCAN
    dbscan = DBSCAN(eps=0.3, min_samples=5)
    dbscan_pred = dbscan.fit_predict(X_scaled)
    dbscan_outliers = np.where(dbscan_pred == -1)
    
    # PCA for visualization
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)
    
    return iso_outliers, kmeans_outliers, dbscan_outliers, X_pca

# פונקציה לשמירה ויזואלית של נתונים
def save_data(positions, rssi_values, attacker_position):
    data = {
        "positions": positions,
        "rssi_values": rssi_values,
        "attacker_position": attacker_position
    }
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"history/data_{timestamp}.json", "w") as f:
        json.dump(data, f, indent=4)
    print("Data saved to history")

# פונקציה להצגת הפצה של RSSI
def plot_rssi_distribution(rssi_values, iso_outliers, kmeans_outliers, dbscan_outliers, X_pca):
    plt.clf()
    plt.hist(rssi_values, bins=20, alpha=0.5, label='RSSI')
    plt.hist([rssi_values[i] for i in iso_outliers[0]], bins=20, alpha=0.5, label='Isolation Forest Outliers')
    plt.hist([rssi_values[i] for i in kmeans_outliers[0]], bins=20, alpha=0.5, label='KMeans Outliers')
    plt.hist([rssi_values[i] for i in dbscan_outliers[0]], bins=20, alpha=0.5, label='DBSCAN Outliers')
    plt.title('RSSI Distribution')
    plt.xlabel('RSSI')
    plt.ylabel('Frequency')
    plt.legend()
    
    # PCA Scatter Plot
    plt.figure()
    plt.scatter(X_pca[:, 0], X_pca[:, 1], alpha=0.5)
    plt.title('PCA of RSSI Data')
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.draw()

# פונקציה לניהול ניטור
async def monitor_network(canvas):
    interface_list = ['wlan0', 'wlan1', 'wlan2', 'wlan3']
    positions = [(32.0853, 34.7818), (32.0800, 34.7800), (32.0900, 34.7900), (32.0840, 34.7850)]  # מיקומים ידועים של TP-Link

    while True:
        start_time = time.time()

        # איסוף נתוני RSSI
        rssi_data = await collect_rssi_data(interface_list)
        rssi_values = [rssi for values in rssi_data.values() for rssi in values]

        # חישוב מיקום התוקף
        distances = [rssi_to_distance(np.mean(rssi_values)) for rssi_values in rssi_data.values() if rssi_values]
        attacker_position = trilaterate(positions, distances)
        print("Estimated Attacker Position:", attacker_position)

        # הצגת המידע על מפה
        display_map(positions, attacker_position)

        # ניתוח מתקפות
        iso_outliers, kmeans_outliers, dbscan_outliers, X_pca = analyze_rssi(rssi_values)
        print("Isolation Forest Outliers detected:", iso_outliers)
        print("KMeans Outliers detected:", kmeans_outliers)
        print("DBSCAN Outliers detected:", dbscan_outliers)
        
        save_data(positions, rssi_values, attacker_position)
        
        # הצגת הפצת ה-RSSI בגרף
        plot_rssi_distribution(rssi_values, iso_outliers, kmeans_outliers, dbscan_outliers, X_pca)
        canvas.draw()

        elapsed_time = time.time() - start_time
        sleep_time = max(0, 10 - elapsed_time)  # המתנה עד 10 שניות
        await asyncio.sleep(sleep_time)

# פונקציה לזיהוי מתקפות כגון Handshake, PMKID ועוד
def detect_attacks(packet):
    if packet.haslayer(Dot11):
        # Handshake Attack
        if packet.type == 0 and packet.subtype == 4:
            print("Detected a Handshake attack!")
            return True
        # PMKID Attack
        if packet.type == 0 and packet.subtype == 8:
            if packet[Dot11].info.startswith(b'\x88'):
                print("Detected a PMKID attack!")
                return True
    return False

# פונקציה ללכידת מנות לזיהוי מתקפות
def capture_packets(interface, stop_event):
    def packet_handler(packet):
        if detect_attacks(packet):
            messagebox.showwarning("Attack Detected", "A potential attack has been detected!")
            # Here you can add code to respond to the attack, e.g., block the attacker, send alert, etc.

    sniff(iface=interface, prn=packet_handler, stop_filter=lambda x: stop_event.is_set())

# יצירת GUI באמצעות Tkinter
def create_gui():
    root = tk.Tk()
    root.title("WiFi Attack Monitor")

    tk.Label(root, text="WiFi Attack Monitor", font=("Helvetica", 16)).pack(pady=10)

    map_frame = tk.Frame(root)
    map_frame.pack(pady=10)

    fig, ax = plt.subplots(figsize=(6, 4), dpi=100)
    canvas = FigureCanvasTkAgg(fig, master=map_frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def start_monitoring():
        stop_event = threading.Event()
        monitor_thread = threading.Thread(target=lambda: asyncio.run(monitor_network(canvas)))
        monitor_thread.start()
        capture_threads = []
        for iface in ['wlan0', 'wlan1', 'wlan2', 'wlan3']:
            stop_event = threading.Event()
            capture_thread = threading.Thread(target=lambda: capture_packets(iface, stop_event))
            capture_thread.start()
            capture_threads.append(capture_thread)
        
        root.after(1000, lambda: [t.join() for t in capture_threads])

    tk.Button(root, text="Start Monitoring", command=start_monitoring).pack(pady=10)
    
    root.mainloop()

# הפעלת הממשק הגרפי
create_gui()
