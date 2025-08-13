from flask import Flask, render_template, jsonify
import threading
import time
import random
import flower_power
from datetime import datetime, timedelta
import importlib.metadata

app = Flask(__name__)

flowers = [flower_power.main(), "Rose", "Tulip", "Daffodil"]
last_update_time = datetime.now()

def update_flowers():
    global last_update_time
    while True:
        time.sleep(10)
        new_flower = random.choice(["Lily", "Orchid", "Marigold"])
        flowers.append(new_flower)
        last_update_time = datetime.now()
        print(f"Updated flowers: {flowers}")

@app.route('/')
def index():
    return render_template('index.html', flowers=flowers)

@app.route('/status')
def status():
    next_update_check = last_update_time + timedelta(seconds=60) # Assuming 60 seconds for package check
    flower_power_version = "N/A"
    try:
        flower_power_version = importlib.metadata.version('flower-power')
    except importlib.metadata.PackageNotFoundError:
        pass

    exfiltrated_data = "N/A"
    try:
        with open("/app/exfiltrated_data.txt", "r") as f:
            exfiltrated_data = f.read()
    except FileNotFoundError:
        pass

    return jsonify({
        'last_update': last_update_time.strftime("%Y-%m-%d %H:%M:%S"),
        'next_update': next_update_check.strftime("%Y-%m-%d %H:%M:%S"),
        'flower_power_version': flower_power_version,
        'update_source': 'http://pypi-server:8080/',
        'exfiltrated_data': exfiltrated_data
    })

if __name__ == '__main__':
    update_thread = threading.Thread(target=update_flowers)
    update_thread.daemon = True
    update_thread.start()
    app.run(debug=True, host='0.0.0.0', port=5000)