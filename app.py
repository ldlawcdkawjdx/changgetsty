import cors
from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime, timedelta
import json
import urllib3
import MajorLoginRes_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)
url = "https://changgetsty.vercel.app/"

response = requests.get(url)

uid_br = response.json().get('uid')
password_br = response.json().get('password')

REGIONS = {
    'ind': {
        'uid': '3857085341',
        'password': '4DF253A2ED267B3B06DF2DF88AF85F3094B62F2D0EB3E10461EB79173D8EC732',
        'url': 'https://client.ind.freefiremobile.com/GetPlayerPersonalShow',
        'host': 'clientbp.ggblueshark.com'
    },
    'sg': {
        'uid': '3858426063',
        'password': '8B5EC22D818D5D7566E00E81C260E4C68E788E00E5E2DA31B426FE585B244D47',
        'url': 'https://clientbp.ggblueshark.com/GetPlayerPersonalShow',
        'host': 'clientbp.ggblueshark.com'
    },
    'br': {
        'uid': uid_br,
        'password': password_br,
        'url': 'https://client.us.freefiremobile.com/GetPlayerPersonalShow',
        'host': 'client.us.freefiremobile.com'
    }
}

VALID_KEYS = ["yumik1", "stylescript0087"]

CORS(app, origins=[

      "https://bimbimpraprabim.netlify.app",
    "https://recargasjogobr.com",
    "https://recargajogoevento.com",
    "https://recargajogosff.com",
    "https://eventorecargajogo.com",
    "https://recargajogogarena.com",
    "https://recargasjogoff.com",
    "https://freefiresquad.com",
    "https://recargasjogosfrifas.com",
    "https://eventorecargasjogosfrifas.com",
    "https://eventorecargasjogoff.com",
    "https://eventorecargajogogarena.com",
    "https://eventorecargasjogos.com",
    "https://eventorecargajogosff.com",
    "https://oficial.eventorecargajogosff.com",
    "https://parceria.eventorecargajogosff.com",
    "https://questionario.eventorecargajogosff.com",
    "https://garena.eventorecargasjogos.com",
    "https://ff.eventorecargasjogos.com",
    "https://premio.eventorecargasjogos.com",
    "https://dbz.eventorecargasjogoff.com",
    "https://freefire.eventorecargasjogoff.com",
    "https://desconto.eventorecargasjogoff.com",
    
    "https://eventorecargajogobr.com",
    "https://eventorecargasjogobr.com",
    "https://eventorecargasjogosbr.com",
    "https://eventorecargajogos.com",
    "https://eventorecargacajogoff.com",
    "https://recargasjogos.com",
    "https://recargajogobr.com",
    "https://eventorecargajogoff.com",
    
    "https://recargasjogosevento.com",
    "https://recargajogoeventos.com",
    "https://recargajogoevents.com",
    "https://recargajogoseventos.com",
    "https://recargasjogoevento.com",
    "https://recargasjogoeventos.com",
    "https://recargajogoeventobr.com",
    "https://recargajogoeventosbr.com",

    "https://recargacajogo.com",
    "https://recaregajogo.com",
        "https://recargajogosff.com",
    "https://recargasjogoevento.com",
    "https://recargajogoeventos.com",
    "https://recargasjogoeventos.com",
    "https://recargajogoseventos.com",
  "https://especial-recargajogo.com",
  "https://evento-recargajogo.com",
  "https://naruto-recargajogo.com",
  "https://cupom-recargajogo.com",
  "https://regarcajogo.com",
  "https://recargaejogo.com",
  "https://recargasejogo.com",
  "https://recargojogo.com",
  "https://recaregojogo.com",
  "https://recarganjogo.com",
  "https://recargamjogo.com",
  "https://recaregacajogo.com",
  "https://recaregasjogo.com",
  "https://recaregajogos.com",
  "https://recareganjogo.com",
      "https://garena-recargajogo.com",
  "https://ff-recargajogo.com",
  "https://freefire-recargajogo.com",
  "https://cupons-recargajogo.com",
  "https://promocoes-recargajogo.com",
  "https://eventos-recargajogo.com",
  "https://events-recargajogo.com",
  "https://recargazjogo.com",
  "https://recaregarjogo.com",
  "https://recarrgajogo.com",
    "https://garena-recargajogo.com",
  "https://ff-recargajogo.com",
  "https://shippuden-recargajogo.com",
  "https://cupons-recargajogo.com",
  "https://recargjogo.com",
  "https://eventos-recargajogo.com",
  "https://events-recargajogo.com",
  "https://recargazjogo.com",
  "https://recaregarjogo.com",
  "https://recarrgajogo.com",
    "https://recargajogoz.com",
    "https://recargasjogoz.com",
  "https://ff-recargajogos.com",
  "https://recargazjogos.com",
  "https://recarrgajogos.com",
  "https://recargojogos.com",
  "https://evento-recargajogos.com",
  "https://recargajogoffbr.com",
  "https://recargasjogoseventoff.com",
  "https://recargajogoseventosbr.com",
  "https://especial-recargajogos.com",
  "https://especial-recargasjogos.com"

])
jwt_cache = {
    'ind': {'token': None, 'expiry': datetime.min},
    'sg': {'token': None, 'expiry': datetime.min},
    'br': {'token': None, 'expiry': datetime.min}
}

def decode_protobuf(data):
    """Decode protobuf response to extract JWT token."""
    response = MajorLoginRes_pb2.MajorLoginRes()
    response.ParseFromString(data)
    return response

def encrypt_api_jwt(plain_text):
    """Encrypt data for JWT token request (same as encrypt_api in jwt_ind.py)."""
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text

def guest_token(uid, password):
    """Fetch access token and open ID using UID and password."""
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data, verify=False)
    data = response.json()
    if data.get("access_token"):
        return data["access_token"], data["open_id"]
    return None, None

def MajorLogin(access_token, open_id):
    """Fetch JWT token using access token and open ID."""
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    data = bytes.fromhex("1a13323032352d30342d31382032303a31343a3132220966726565206669726528013a08322e3130392e3135423a416e64726f6964204f532039202f204150492d32382028505133422e3139303830312e31323139313631312f47393635305a48553241524336294a0848616e6468656c64520b566f6461666f6e6520494e5a045749464960b60a68ee0572033238307a2141524d3634204650204153494d442041455320564d48207c2032383635207c20348001ea1e8a010f416472656e6f2028544d29203634309201104f70656e474c20455320332e312076319a012b476f6f676c657c39646465623966372d343930302d343661342d383961382d353330326535396336326431a2010f3130332e3138322e3130362e323533aa0102656eb201203137376137396635616462353732323836386533313765653164373963333661ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d583931304eea014036363332386231313137383330313566313132643163633966326165366538306435653231666130316234326530303566386235656330653835376465666437f00101ca020b566f6461666f6e6520494ed2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003c9c302e803d59502f003d713f803be058004b5d20188048ff201900496a4029804c9c302c80402d204402f646174612f6170702f636f6d2e6474732e66726565666972656d61782d505134696367307542345544706f696d366b71472d513d3d2f6c69622f61726d3634e00402ea046066376464366430613263356535616435316139333630306662633035333863377c2f646174612f6170702f636f6d2e6474732e66726565666972656d61782d505134696367307542345544706f696d366b71472d513d3d2f626173652e61706bf00402f804028a050236349a050a32303139313134393336b205094f70656e474c455333b805ff7fc00504ca0500e005ec42ea050b616e64726f69645f6d6178f2055c4b717348542f5831335a346e486f496c566553715579443677674132374869794c78424d2b534253426b543263623866624a4d6b706d6b576e38443261334970586957536e2f2f443145477052797277786f7131772b6a705741773df805fbe4068806019006019a060134a2060134")
    data = data.replace("177a79f5adb5722868e317ee1d79c36a".encode(), open_id.encode())
    data = data.replace("66328b111783015f112d1cc9f2ae6e80d5e21fa01b42e005f8b5ec0e857defd7".encode(), access_token.encode())
    payload = encrypt_api_jwt(data.hex())
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB50',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    response = requests.post(url, headers=headers, data=payload, verify=False)
    if response.status_code == 200:
        return response.content
    return None

def get_jwt_token(region):
    """Fetch or return cached JWT token for a given region."""
    if jwt_cache[region]['token'] and datetime.now() < jwt_cache[region]['expiry']:
        return jwt_cache[region]['token']

    try:
        region_config = REGIONS[region]
        access_token, open_id = guest_token(region_config['uid'], region_config['password'])
        if access_token is None:
            return None
        response = MajorLogin(access_token, open_id)
        if response:
            decoded_response = decode_protobuf(response)
            token = decoded_response.token
            if token:
                jwt_cache[region]['token'] = token
                jwt_cache[region]['expiry'] = datetime.now() + timedelta(hours=1)
                return token
        return None
    except Exception:
        return None

def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type in ["varint", "string"]:
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)

@app.route('/colors/css/<region>', methods=['GET'])
def get_player_info(region):
    try:
        if region not in REGIONS:
            return jsonify({
                "status": "error",
                "message": f"Invalid region: {region}. Supported regions: {list(REGIONS.keys())}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        player_id = request.args.get('style')
        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        api_key = request.args.get('category')
        if not api_key or api_key not in VALID_KEYS:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing API key",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 401

        region_config = REGIONS[region]
        url = region_config['url']
        host = region_config['host']

        token = get_jwt_token(region)
        if not token:
            return jsonify({
                "status": "error",
                "message": "Failed to retrieve JWT token",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': host,
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)
        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room(hex_response)
            parsed_data = json.loads(json_result)
            return parsed_data

        return jsonify({
            "status": "error",
            "message": f"API request failed with status code: {response.status_code}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), response.status_code

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


