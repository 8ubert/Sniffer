import socket
import json
from flask import Flask, request, jsonify
from pymongo import MongoClient
from threading import Thread

sniffer = Flask(__name__)

try:
    client = MongoClient('mongodb://localhost:27017/')
    db = client['intercepted_data']
    collection = db['packets']
except Exception as e:
    print(f"Erro ao conectar ao MongoDB: {str(e)}")

interception_running = False
sniffer_socket = None

@sniffer.route('/start_interception', methods=['POST'])
def start_interception():
    global interception_running, sniffer_socket
    
    if interception_running:
        return jsonify({'message': 'Interceptação já está ativada.'})
    
    interception_running = True
    sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    sniffer_socket.bind(("192.168.0.27", 5000))
    
    capture_thread = Thread(target=capture_packets)
    capture_thread.start()
    
    return jsonify({'message': 'Interceptação iniciada.'})

@sniffer.route('/stop_interception', methods=['POST'])
def stop_interception():
    global interception_running, sniffer_socket
    
    if not interception_running:
        return jsonify({'message': 'Interceptação já está parada.'})
    
    interception_running = False

    if sniffer_socket:
        sniffer_socket = None
    
    return jsonify({'message': 'Interceptação parada.'})

@sniffer.route('/get_data', methods=['GET'])
def get_data():
    data = list(collection.find({}, {'_id': 0}))
    return jsonify(data)

def capture_packets():
    global interception_running, sniffer_socket
    
    while interception_running:
        try:
            packet, addr = sniffer_socket.recvfrom(65535)
            print(f"Origem: {addr[0]}, Dados: {packet[:16].hex()}")
            
            packet_data = {
                'src': addr[0],
                'data': packet.hex()
            }
            
            json_data = json.dumps(packet_data)
            
            result = collection.insert_one(json.loads(json_data))
            if result.acknowledged:
                print("Pacote armazenado no MongoDB com sucesso.")
            else:
                print("Inserção no MongoDB falhou.")
        
        except socket.error as e:
            print(f"Erro ao capturar pacote: {str(e)}")

def main():
    sniffer.run(host="192.168.0.27", port=5000, debug=True)

if __name__ == '__main__':
    main()
