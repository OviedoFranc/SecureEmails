from flask import Flask, request, jsonify

app = Flask(__name__)
#por problemas de ascii seteo utf, la ñ no la toma por ejemplo en contraseña sino al mostrar el json
app.json.mimetype = "application/json; charset=utf-8"
data_recv = []

@app.route("/", methods=['POST', 'GET'])
def home():
    if request.method == 'POST':
        data = request.get_json() 
        if not data:
            return jsonify({"error no data send"}), 400
        data_recv.append(data)
        return jsonify({"data received"}), 200

    elif request.method == 'GET':
        return jsonify(data_recv), 200

if __name__ == '__main__':
  app.run(host='0.0.0.0', debug=True, port=5555)