from flask import Flask, request, jsonify

app = Flask(__name__)
data_recv = []

@app.route("/", methods=['POST', 'GET'])
def home():
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({"error no data send"}), 400
        data_recv.append(data)

    elif request.method == 'GET':
        return jsonify(data_recv), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5555)