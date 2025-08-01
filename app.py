from flask import Flask, jsonify, abort
import json
from datetime import datetime

app = Flask(__name__)
ACCOUNTS_FILE = 'accounts.json'

def load_accounts():
    with open(ACCOUNTS_FILE, 'r') as f:
        return json.load(f)

@app.route('/', methods=['GET'])
def get_daily_account():
    accounts = load_accounts()
    day = datetime.now().day
    index = day - 1 

    if index >= len(accounts):
        return jsonify({
            "error": "No account available for today. Only {} accounts present.".format(len(accounts))
        }), 404

    return jsonify(accounts[index])

if __name__ == '__main__':
    app.run(debug=True, port=5000)
