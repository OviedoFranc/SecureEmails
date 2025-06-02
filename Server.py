from flask import Flask, request, jsonify, Response
import json

app = Flask(__name__)
data_recv = []

@app.route("/", methods=['POST', 'GET'])
def home():
    if request.method == 'POST':
        data = request.get_json() 
        if not data:
            return jsonify({"error": "no data sent"}), 400
        data_recv.append(data)
        return jsonify({"message": "data received"}), 200

    elif request.method == 'GET':
        response = Response(
            json.dumps(data_recv, ensure_ascii=False),
            mimetype='application/json; charset=utf-8',
            status=200
        )
        return response

if __name__ == '__main__':
  app.run(host='0.0.0.0', debug=True, port=5555)