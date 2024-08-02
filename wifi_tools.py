import numpy as np
from scipy.optimize import minimize
import folium
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import json
from datetime import datetime
import os
import time
import subprocess
import threading
import asyncio
from scapy.all import sniff, Dot11
from geopy.distance import great_circle

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

# פונקציה לניהול מתקפות באמצעות Scapy
def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.getlayer(Dot11).type == 0 and pkt.getlayer(Dot11).subtype == 4:
            print("Deauthentication Attack Detected!")
        elif pkt.getlayer(Dot11).type == 2 and pkt.getlayer(Dot11).subtype == 8:
            print("Handshake Capture Detected!")

# פונקציה לאיסוף נתוני RSSI מכרטיסי רשת
async def collect_rssi_data(interface_list):
    rssi_data = {}
    for iface in interface_list:
        cmd = f"iwconfig {iface} | grep 'Signal level'"
        try:
            output = subprocess.check_output(cmd, shell=True).decode()
            rssi_values = [int(line.split()[-1].replace('dBm', '')) for line in output.split('\n') if 'Signal level' in line]
            rssi_data[iface] = rssi_values
        except subprocess.CalledProcessError:
            rssi_data[iface] = []
    return rssi_data

# פונקציה להצגת המיקום על מפה
def display_map(positions, attacker_position):
    mymap = folium.Map(location=[np.mean([pos[0] for pos in positions]), np.mean([pos[1] for pos in positions])], zoom_start=15)
    for pos in positions:
        folium.Marker(location=pos, popup="TP-Link", icon=folium.Icon(color='blue')).add_to(mymap)
    folium.Marker(location=attacker_position, popup="Attacker Position", icon=folium.Icon(color='red')).add_to(mymap)
    mymap.save("wifi_attack_map.html")

# פונקציה לניתוח מתקפות באמצעות Isolation Forest
def analyze_rssi(rssi_values):
    X = np.array([[rssi] for rssi in rssi_values])
    model = IsolationForest()
    model.fit(X)
    y_pred = model.predict(X)
    outliers = np.where(y_pred == -1)
    return outliers

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
def plot_rssi_distribution(rssi_values):
    plt.hist(rssi_values, bins=20)
    plt.title('RSSI Distribution')
    plt.xlabel('RSSI')
    plt.ylabel('Frequency')
    plt.savefig('rssi_distribution.png')
    plt.show()

# פונקציה לניהול ניטור
async def monitor_network():
    interface_list = ['wlan0', 'wlan1', 'wlan2', 'wlan3']
    positions = [(32.0853, 34.7818), (32.0800, 34.7800), (32.0900, 34.7900)]  # מיקומים ידועים של TP-Link

    # התחלת ניטור חבילות
    sniff(prn=packet_handler, iface='wlan0', store=0, timeout=10)

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
        detect_deauthentication_attack('wifi_traffic.log')
        detect_handshake_capture('handshake_captures/')

        # ניתוח ויזואלי של RSSI
        outliers = analyze_rssi(rssi_values)
        print("Outliers detected:", outliers)
        save_data(positions, rssi_values, attacker_position)
        plot_rssi_distribution(rssi_values)

        elapsed_time = time.time() - start_time
        sleep_time = max(0, 10 - elapsed_time)  # המתנה עד 10 שניות
        await asyncio.sleep(sleep_time)

# התחלת ניטור
asyncio.run(monitor_network())
