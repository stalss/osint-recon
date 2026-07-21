"""
Phone number intelligence module.

Inspired by SpiderFoot's phone number analysis:
- Format detection (international, national)
- Country code identification
- Number type detection (mobile, landline, VoIP)
- Validation and normalization
- Carrier/operator identification (Indian numbers)
- Telecom circle/state lookup (Indian numbers)
- Web search for public records

Features:
- International format detection
- Country code extraction
- Number length validation
- Format normalization
- Indian carrier detection (Jio, Airtel, Vi, BSNL, etc.)
- Indian telecom circle identification
- DuckDuckGo search for public mentions
"""

import re
import urllib.parse
from osint_recon.colors import Colors, Status
from osint_recon.http_client import HTTPClient


# Country codes mapping (common ones)
COUNTRY_CODES = {
    "1": "United States/Canada",
    "7": "Russia",
    "20": "Egypt",
    "27": "South Africa",
    "30": "Greece",
    "31": "Netherlands",
    "32": "Belgium",
    "33": "France",
    "34": "Spain",
    "36": "Hungary",
    "39": "Italy",
    "44": "United Kingdom",
    "46": "Sweden",
    "49": "Germany",
    "52": "Mexico",
    "55": "Brazil",
    "61": "Australia",
    "62": "Indonesia",
    "63": "Philippines",
    "65": "Singapore",
    "81": "Japan",
    "82": "South Korea",
    "86": "China",
    "90": "Turkey",
    "91": "India",
    "92": "Pakistan",
    "93": "Afghanistan",
    "94": "Sri Lanka",
    "95": "Myanmar",
    "212": "Morocco",
    "213": "Algeria",
    "216": "Tunisia",
    "218": "Libya",
    "220": "Gambia",
    "221": "Senegal",
    "222": "Mauritania",
    "223": "Mali",
    "224": "Guinea",
    "225": "Ivory Coast",
    "226": "Burkina Faso",
    "227": "Niger",
    "228": "Togo",
    "229": "Benin",
    "230": "Mauritius",
    "231": "Liberia",
    "232": "Sierra Leone",
    "233": "Ghana",
    "234": "Nigeria",
    "235": "Chad",
    "236": "Central African Republic",
    "237": "Cameroon",
    "238": "Cape Verde",
    "239": "Sao Tome and Principe",
    "240": "Equatorial Guinea",
    "241": "Gabon",
    "242": "Congo",
    "243": "Dem. Rep. Congo",
    "244": "Angola",
    "245": "Guinea-Bissau",
    "246": "Diego Garcia",
    "247": "Ascension Island",
    "248": "Seychelles",
    "249": "Sudan",
    "250": "Rwanda",
    "251": "Ethiopia",
    "252": "Somalia",
    "253": "Djibouti",
    "254": "Kenya",
    "255": "Tanzania",
    "256": "Uganda",
    "257": "Burundi",
    "258": "Mozambique",
    "260": "Zambia",
    "261": "Madagascar",
    "262": "Reunion",
    "263": "Zimbabwe",
    "264": "Namibia",
    "265": "Malawi",
    "266": "Lesotho",
    "267": "Botswana",
    "268": "Eswatini",
    "269": "Comoros",
    "290": "Saint Helena",
    "291": "Eritrea",
    "297": "Aruba",
    "298": "Faroe Islands",
    "299": "Greenland",
    "350": "Gibraltar",
    "351": "Portugal",
    "352": "Luxembourg",
    "353": "Ireland",
    "354": "Iceland",
    "355": "Albania",
    "356": "Malta",
    "357": "Cyprus",
    "358": "Finland",
    "359": "Bulgaria",
    "370": "Lithuania",
    "371": "Latvia",
    "372": "Estonia",
    "373": "Moldova",
    "374": "Armenia",
    "375": "Belarus",
    "376": "Andorra",
    "377": "Monaco",
    "378": "San Marino",
    "380": "Ukraine",
    "381": "Serbia",
    "382": "Montenegro",
    "385": "Croatia",
    "386": "Slovenia",
    "387": "Bosnia and Herzegovina",
    "389": "North Macedonia",
    "420": "Czech Republic",
    "421": "Slovakia",
    "960": "Maldives",
    "961": "Lebanon",
    "962": "Jordan",
    "963": "Syria",
    "964": "Iraq",
    "965": "Kuwait",
    "966": "Saudi Arabia",
    "967": "Yemen",
    "968": "Oman",
    "971": "United Arab Emirates",
    "972": "Israel",
    "973": "Bahrain",
    "974": "Qatar",
    "975": "Bhutan",
    "976": "Mongolia",
    "977": "Nepal",
    "992": "Tajikistan",
    "993": "Turkmenistan",
    "994": "Azerbaijan",
    "995": "Georgia",
    "996": "Kyrgyzstan",
    "998": "Uzbekistan",
}


# Indian mobile carrier prefixes (first 4 digits after +91)
# Note: MNP (Mobile Number Portability) means users can switch carriers,
# so these are initial allocations, not current carrier guarantees.
INDIAN_CARRIERS = {
    # Jio (Reliance Jio Infocomm)
    "7000": "Jio", "7001": "Jio", "7002": "Jio", "7003": "Jio",
    "7004": "Jio", "7005": "Jio", "7006": "Jio", "7007": "Jio",
    "7008": "Jio", "7009": "Jio", "7010": "Jio", "7011": "Jio",
    "7012": "Jio", "7013": "Jio", "7014": "Jio", "7015": "Jio",
    "7016": "Jio", "7017": "Jio", "7018": "Jio", "7019": "Jio",
    "7020": "Jio", "7021": "Jio", "7022": "Jio", "7023": "Jio",
    "7024": "Jio", "7025": "Jio", "7026": "Jio", "7027": "Jio",
    "7028": "Jio", "7029": "Jio", "7030": "Jio", "7031": "Jio",
    "7032": "Jio", "7033": "Jio", "7034": "Jio", "7035": "Jio",
    "7036": "Jio", "7037": "Jio", "7038": "Jio", "7039": "Jio",
    "7040": "Jio", "7041": "Jio", "7042": "Jio", "7043": "Jio",
    "7044": "Jio", "7045": "Jio", "7046": "Jio", "7047": "Jio",
    "7048": "Jio", "7049": "Jio", "7050": "Jio", "7051": "Jio",
    "7052": "Jio", "7053": "Jio", "7054": "Jio", "7055": "Jio",
    "7056": "Jio", "7057": "Jio", "7058": "Jio", "7059": "Jio",
    "7060": "Jio", "7061": "Jio", "7062": "Jio", "7063": "Jio",
    "7064": "Jio", "7065": "Jio", "7066": "Jio", "7067": "Jio",
    "7068": "Jio", "7069": "Jio", "7070": "Jio", "7071": "Jio",
    "7072": "Jio", "7073": "Jio", "7074": "Jio", "7075": "Jio",
    "7076": "Jio", "7077": "Jio", "7078": "Jio", "7079": "Jio",
    "7080": "Jio", "7081": "Jio", "7082": "Jio", "7083": "Jio",
    "7084": "Jio", "7085": "Jio", "7086": "Jio", "7087": "Jio",
    "7088": "Jio", "7089": "Jio", "7090": "Jio", "7091": "Jio",
    "7092": "Jio", "7093": "Jio", "7094": "Jio", "7095": "Jio",
    "7096": "Jio", "7097": "Jio", "7098": "Jio", "7099": "Jio",
    "7300": "Jio", "7301": "Jio", "7302": "Jio", "7303": "Jio",
    "7304": "Jio", "7305": "Jio", "7306": "Jio", "7307": "Jio",
    "7308": "Jio", "7309": "Jio", "7310": "Jio", "7311": "Jio",
    "7312": "Jio", "7313": "Jio", "7314": "Jio", "7315": "Jio",
    "7316": "Jio", "7317": "Jio", "7318": "Jio", "7319": "Jio",
    "7350": "Jio", "7351": "Jio", "7352": "Jio", "7353": "Jio",
    "7354": "Jio", "7355": "Jio", "7356": "Jio", "7357": "Jio",
    "7358": "Jio", "7359": "Jio", "7360": "Jio", "7361": "Jio",
    "7362": "Jio", "7363": "Jio", "7364": "Jio", "7365": "Jio",
    "7366": "Jio", "7367": "Jio", "7368": "Jio", "7369": "Jio",
    "7370": "Jio", "7371": "Jio", "7372": "Jio", "7373": "Jio",
    "7374": "Jio", "7375": "Jio", "7376": "Jio", "7377": "Jio",
    "7378": "Jio", "7379": "Jio", "7380": "Jio", "7381": "Jio",
    "7382": "Jio", "7383": "Jio", "7384": "Jio", "7385": "Jio",
    "7386": "Jio", "7387": "Jio", "7388": "Jio", "7389": "Jio",
    "7390": "Jio", "7391": "Jio", "7392": "Jio", "7393": "Jio",
    "7394": "Jio", "7395": "Jio", "7396": "Jio", "7397": "Jio",
    "7398": "Jio", "7399": "Jio",
    "8900": "Jio", "8901": "Jio", "8902": "Jio", "8903": "Jio",
    "8904": "Jio", "8905": "Jio", "8906": "Jio", "8907": "Jio",
    "8908": "Jio", "8909": "Jio", "8910": "Jio", "8911": "Jio",
    "8912": "Jio", "8913": "Jio", "8914": "Jio", "8915": "Jio",
    "8916": "Jio", "8917": "Jio", "8918": "Jio", "8919": "Jio",
    "8920": "Jio", "8921": "Jio", "8922": "Jio", "8923": "Jio",
    "8924": "Jio", "8925": "Jio", "8926": "Jio", "8927": "Jio",
    "8928": "Jio", "8929": "Jio", "8930": "Jio", "8931": "Jio",
    "8932": "Jio", "8933": "Jio", "8934": "Jio", "8935": "Jio",
    "8936": "Jio", "8937": "Jio", "8938": "Jio", "8939": "Jio",
    "8940": "Jio", "8941": "Jio", "8942": "Jio", "8943": "Jio",
    "8944": "Jio", "8945": "Jio", "8946": "Jio", "8947": "Jio",
    "8948": "Jio", "8949": "Jio", "8950": "Jio", "8951": "Jio",
    "8952": "Jio", "8953": "Jio", "8954": "Jio", "8955": "Jio",
    "8956": "Jio", "8957": "Jio", "8958": "Jio", "8959": "Jio",
    "8960": "Jio", "8961": "Jio", "8962": "Jio", "8963": "Jio",
    "8964": "Jio", "8965": "Jio", "8966": "Jio", "8967": "Jio",
    "8968": "Jio", "8969": "Jio", "8970": "Jio", "8971": "Jio",
    "8972": "Jio", "8973": "Jio", "8974": "Jio", "8975": "Jio",
    "8976": "Jio", "8977": "Jio", "8978": "Jio", "8979": "Jio",
    "8980": "Jio", "8981": "Jio", "8982": "Jio", "8983": "Jio",
    "8984": "Jio", "8985": "Jio", "8986": "Jio", "8987": "Jio",
    "8988": "Jio", "8989": "Jio", "8990": "Jio", "8991": "Jio",
    "8992": "Jio", "8993": "Jio", "8994": "Jio", "8995": "Jio",
    "8996": "Jio", "8997": "Jio", "8998": "Jio", "8999": "Jio",
    "6200": "Jio", "6201": "Jio", "6202": "Jio", "6203": "Jio",
    "6204": "Jio", "6205": "Jio", "6206": "Jio", "6207": "Jio",
    "6208": "Jio", "6209": "Jio", "6260": "Jio", "6261": "Jio",
    "6262": "Jio", "6263": "Jio", "6264": "Jio", "6265": "Jio",
    "6266": "Jio", "6267": "Jio", "6268": "Jio", "6269": "Jio",
    "6290": "Jio", "6291": "Jio", "6292": "Jio", "6293": "Jio",
    "6294": "Jio", "6295": "Jio", "6296": "Jio", "6297": "Jio",
    "6298": "Jio", "6299": "Jio",
    # Airtel (Bharti Airtel)
    "8100": "Airtel", "8101": "Airtel", "8102": "Airtel", "8103": "Airtel",
    "8104": "Airtel", "8105": "Airtel", "8106": "Airtel", "8107": "Airtel",
    "8108": "Airtel", "8109": "Airtel", "8120": "Airtel", "8121": "Airtel",
    "8122": "Airtel", "8123": "Airtel", "8124": "Airtel", "8125": "Airtel",
    "8126": "Airtel", "8127": "Airtel", "8128": "Airtel", "8129": "Airtel",
    "8130": "Airtel", "8131": "Airtel", "8132": "Airtel", "8133": "Airtel",
    "8134": "Airtel", "8135": "Airtel", "8136": "Airtel", "8137": "Airtel",
    "8138": "Airtel", "8139": "Airtel", "8140": "Airtel", "8141": "Airtel",
    "8142": "Airtel", "8143": "Airtel", "8144": "Airtel", "8145": "Airtel",
    "8146": "Airtel", "8147": "Airtel", "8148": "Airtel", "8149": "Airtel",
    "8160": "Airtel", "8161": "Airtel", "8162": "Airtel", "8163": "Airtel",
    "8164": "Airtel", "8165": "Airtel", "8166": "Airtel", "8167": "Airtel",
    "8168": "Airtel", "8169": "Airtel", "8170": "Airtel", "8171": "Airtel",
    "8172": "Airtel", "8173": "Airtel", "8174": "Airtel", "8175": "Airtel",
    "8176": "Airtel", "8177": "Airtel", "8178": "Airtel", "8179": "Airtel",
    "8180": "Airtel", "8181": "Airtel", "8182": "Airtel", "8183": "Airtel",
    "8184": "Airtel", "8185": "Airtel", "8186": "Airtel", "8187": "Airtel",
    "8188": "Airtel", "8189": "Airtel", "8190": "Airtel", "8191": "Airtel",
    "8192": "Airtel", "8193": "Airtel", "8194": "Airtel", "8195": "Airtel",
    "8196": "Airtel", "8197": "Airtel", "8198": "Airtel", "8199": "Airtel",
    "9000": "Airtel", "9001": "Airtel", "9002": "Airtel", "9003": "Airtel",
    "9004": "Airtel", "9005": "Airtel", "9006": "Airtel", "9007": "Airtel",
    "9008": "Airtel", "9009": "Airtel", "9010": "Airtel", "9011": "Airtel",
    "9012": "Airtel", "9013": "Airtel", "9014": "Airtel", "9015": "Airtel",
    "9016": "Airtel", "9017": "Airtel", "9018": "Airtel", "9019": "Airtel",
    "9020": "Airtel", "9021": "Airtel", "9022": "Airtel", "9023": "Airtel",
    "9024": "Airtel", "9025": "Airtel", "9026": "Airtel", "9027": "Airtel",
    "9028": "Airtel", "9029": "Airtel", "9030": "Airtel", "9031": "Airtel",
    "9032": "Airtel", "9033": "Airtel", "9034": "Airtel", "9035": "Airtel",
    "9036": "Airtel", "9037": "Airtel", "9038": "Airtel", "9039": "Airtel",
    "9040": "Airtel", "9041": "Airtel", "9042": "Airtel", "9043": "Airtel",
    "9044": "Airtel", "9045": "Airtel", "9046": "Airtel", "9047": "Airtel",
    "9048": "Airtel", "9049": "Airtel", "9050": "Airtel", "9051": "Airtel",
    "9052": "Airtel", "9053": "Airtel", "9054": "Airtel", "9055": "Airtel",
    "9056": "Airtel", "9057": "Airtel", "9058": "Airtel", "9059": "Airtel",
    "9060": "Airtel", "9061": "Airtel", "9062": "Airtel", "9063": "Airtel",
    "9064": "Airtel", "9065": "Airtel", "9066": "Airtel", "9067": "Airtel",
    "9068": "Airtel", "9069": "Airtel", "9070": "Airtel", "9071": "Airtel",
    "9072": "Airtel", "9073": "Airtel", "9074": "Airtel", "9075": "Airtel",
    "9076": "Airtel", "9077": "Airtel", "9078": "Airtel", "9079": "Airtel",
    "9080": "Airtel", "9081": "Airtel", "9082": "Airtel", "9083": "Airtel",
    "9084": "Airtel", "9085": "Airtel", "9086": "Airtel", "9087": "Airtel",
    "9088": "Airtel", "9089": "Airtel", "9090": "Airtel", "9091": "Airtel",
    "9092": "Airtel", "9093": "Airtel", "9094": "Airtel", "9095": "Airtel",
    "9096": "Airtel", "9097": "Airtel", "9098": "Airtel", "9099": "Airtel",
    "9100": "Airtel", "9101": "Airtel", "9102": "Airtel", "9103": "Airtel",
    "9104": "Airtel", "9105": "Airtel", "9106": "Airtel", "9107": "Airtel",
    "9108": "Airtel", "9109": "Airtel", "9110": "Airtel", "9111": "Airtel",
    "9112": "Airtel", "9113": "Airtel", "9114": "Airtel", "9115": "Airtel",
    "9116": "Airtel", "9117": "Airtel", "9118": "Airtel", "9119": "Airtel",
    "9120": "Airtel", "9121": "Airtel", "9122": "Airtel", "9123": "Airtel",
    "9124": "Airtel", "9125": "Airtel", "9126": "Airtel", "9127": "Airtel",
    "9128": "Airtel", "9129": "Airtel", "9130": "Airtel", "9131": "Airtel",
    "9132": "Airtel", "9133": "Airtel", "9134": "Airtel", "9135": "Airtel",
    "9136": "Airtel", "9137": "Airtel", "9138": "Airtel", "9139": "Airtel",
    "9140": "Airtel", "9141": "Airtel", "9142": "Airtel", "9143": "Airtel",
    "9144": "Airtel", "9145": "Airtel", "9146": "Airtel", "9147": "Airtel",
    "9148": "Airtel", "9149": "Airtel", "9150": "Airtel", "9151": "Airtel",
    "9152": "Airtel", "9153": "Airtel", "9154": "Airtel", "9155": "Airtel",
    "9156": "Airtel", "9157": "Airtel", "9158": "Airtel", "9159": "Airtel",
    "9160": "Airtel", "9161": "Airtel", "9162": "Airtel", "9163": "Airtel",
    "9164": "Airtel", "9165": "Airtel", "9166": "Airtel", "9167": "Airtel",
    "9168": "Airtel", "9169": "Airtel", "9170": "Airtel", "9171": "Airtel",
    "9172": "Airtel", "9173": "Airtel", "9174": "Airtel", "9175": "Airtel",
    "9176": "Airtel", "9177": "Airtel", "9178": "Airtel", "9179": "Airtel",
    "9180": "Airtel", "9181": "Airtel", "9182": "Airtel", "9183": "Airtel",
    "9184": "Airtel", "9185": "Airtel", "9186": "Airtel", "9187": "Airtel",
    "9188": "Airtel", "9189": "Airtel", "9190": "Airtel", "9191": "Airtel",
    "9192": "Airtel", "9193": "Airtel", "9194": "Airtel", "9195": "Airtel",
    "9196": "Airtel", "9197": "Airtel", "9198": "Airtel", "9199": "Airtel",
    "9200": "Airtel", "9201": "Airtel", "9202": "Airtel", "9203": "Airtel",
    "9204": "Airtel", "9205": "Airtel", "9206": "Airtel", "9207": "Airtel",
    "9208": "Airtel", "9209": "Airtel", "9210": "Airtel", "9211": "Airtel",
    "9212": "Airtel", "9213": "Airtel", "9214": "Airtel", "9215": "Airtel",
    "9216": "Airtel", "9217": "Airtel", "9218": "Airtel", "9219": "Airtel",
    "9220": "Airtel", "9221": "Airtel", "9222": "Airtel", "9223": "Airtel",
    "9224": "Airtel", "9225": "Airtel", "9226": "Airtel", "9227": "Airtel",
    "9228": "Airtel", "9229": "Airtel", "9230": "Airtel", "9231": "Airtel",
    "9232": "Airtel", "9233": "Airtel", "9234": "Airtel", "9235": "Airtel",
    "9236": "Airtel", "9237": "Airtel", "9238": "Airtel", "9239": "Airtel",
    "9240": "Airtel", "9241": "Airtel", "9242": "Airtel", "9243": "Airtel",
    "9244": "Airtel", "9245": "Airtel", "9246": "Airtel", "9247": "Airtel",
    "9248": "Airtel", "9249": "Airtel", "9250": "Airtel", "9251": "Airtel",
    "9252": "Airtel", "9253": "Airtel", "9254": "Airtel", "9255": "Airtel",
    "9256": "Airtel", "9257": "Airtel", "9258": "Airtel", "9259": "Airtel",
    "9260": "Airtel", "9261": "Airtel", "9262": "Airtel", "9263": "Airtel",
    "9264": "Airtel", "9265": "Airtel", "9266": "Airtel", "9267": "Airtel",
    "9268": "Airtel", "9269": "Airtel", "9270": "Airtel", "9271": "Airtel",
    "9272": "Airtel", "9273": "Airtel", "9274": "Airtel", "9275": "Airtel",
    "9276": "Airtel", "9277": "Airtel", "9278": "Airtel", "9279": "Airtel",
    "9280": "Airtel", "9281": "Airtel", "9282": "Airtel", "9283": "Airtel",
    "9284": "Airtel", "9285": "Airtel", "9286": "Airtel", "9287": "Airtel",
    "9288": "Airtel", "9289": "Airtel", "9290": "Airtel", "9291": "Airtel",
    "9292": "Airtel", "9293": "Airtel", "9294": "Airtel", "9295": "Airtel",
    "9296": "Airtel", "9297": "Airtel", "9298": "Airtel", "9299": "Airtel",
    "9300": "Airtel", "9301": "Airtel", "9302": "Airtel", "9303": "Airtel",
    "9304": "Airtel", "9305": "Airtel", "9306": "Airtel", "9307": "Airtel",
    "9308": "Airtel", "9309": "Airtel", "9310": "Airtel", "9311": "Airtel",
    "9312": "Airtel", "9313": "Airtel", "9314": "Airtel", "9315": "Airtel",
    "9316": "Airtel", "9317": "Airtel", "9318": "Airtel", "9319": "Airtel",
    "9320": "Airtel", "9321": "Airtel", "9322": "Airtel", "9323": "Airtel",
    "9324": "Airtel", "9325": "Airtel", "9326": "Airtel", "9327": "Airtel",
    "9328": "Airtel", "9329": "Airtel", "9330": "Airtel", "9331": "Airtel",
    "9332": "Airtel", "9333": "Airtel", "9334": "Airtel", "9335": "Airtel",
    "9336": "Airtel", "9337": "Airtel", "9338": "Airtel", "9339": "Airtel",
    "9340": "Airtel", "9341": "Airtel", "9342": "Airtel", "9343": "Airtel",
    "9344": "Airtel", "9345": "Airtel", "9346": "Airtel", "9347": "Airtel",
    "9348": "Airtel", "9349": "Airtel", "9350": "Airtel", "9351": "Airtel",
    "9352": "Airtel", "9353": "Airtel", "9354": "Airtel", "9355": "Airtel",
    "9356": "Airtel", "9357": "Airtel", "9358": "Airtel", "9359": "Airtel",
    "9360": "Airtel", "9361": "Airtel", "9362": "Airtel", "9363": "Airtel",
    "9364": "Airtel", "9365": "Airtel", "9366": "Airtel", "9367": "Airtel",
    "9368": "Airtel", "9369": "Airtel", "9370": "Airtel", "9371": "Airtel",
    "9372": "Airtel", "9373": "Airtel", "9374": "Airtel", "9375": "Airtel",
    "9376": "Airtel", "9377": "Airtel", "9378": "Airtel", "9379": "Airtel",
    "9380": "Airtel", "9381": "Airtel", "9382": "Airtel", "9383": "Airtel",
    "9384": "Airtel", "9385": "Airtel", "9386": "Airtel", "9387": "Airtel",
    "9388": "Airtel", "9389": "Airtel", "9390": "Airtel", "9391": "Airtel",
    "9392": "Airtel", "9393": "Airtel", "9394": "Airtel", "9395": "Airtel",
    "9396": "Airtel", "9397": "Airtel", "9398": "Airtel", "9399": "Airtel",
    "9400": "Airtel", "9401": "Airtel", "9402": "Airtel", "9403": "Airtel",
    "9404": "Airtel", "9405": "Airtel", "9406": "Airtel", "9407": "Airtel",
    "9408": "Airtel", "9409": "Airtel", "9410": "Airtel", "9411": "Airtel",
    "9412": "Airtel", "9413": "Airtel", "9414": "Airtel", "9415": "Airtel",
    "9416": "Airtel", "9417": "Airtel", "9418": "Airtel", "9419": "Airtel",
    "9420": "Airtel", "9421": "Airtel", "9422": "Airtel", "9423": "Airtel",
    "9424": "Airtel", "9425": "Airtel", "9426": "Airtel", "9427": "Airtel",
    "9428": "Airtel", "9429": "Airtel", "9430": "Airtel", "9431": "Airtel",
    "9432": "Airtel", "9433": "Airtel", "9434": "Airtel", "9435": "Airtel",
    "9436": "Airtel", "9437": "Airtel", "9438": "Airtel", "9439": "Airtel",
    "9440": "Airtel", "9441": "Airtel", "9442": "Airtel", "9443": "Airtel",
    "9444": "Airtel", "9445": "Airtel", "9446": "Airtel", "9447": "Airtel",
    "9448": "Airtel", "9449": "Airtel", "9450": "Airtel", "9451": "Airtel",
    "9452": "Airtel", "9453": "Airtel", "9454": "Airtel", "9455": "Airtel",
    "9456": "Airtel", "9457": "Airtel", "9458": "Airtel", "9459": "Airtel",
    "9460": "Airtel", "9461": "Airtel", "9462": "Airtel", "9463": "Airtel",
    "9464": "Airtel", "9465": "Airtel", "9466": "Airtel", "9467": "Airtel",
    "9468": "Airtel", "9469": "Airtel", "9470": "Airtel", "9471": "Airtel",
    "9472": "Airtel", "9473": "Airtel", "9474": "Airtel", "9475": "Airtel",
    "9476": "Airtel", "9477": "Airtel", "9478": "Airtel", "9479": "Airtel",
    "9480": "Airtel", "9481": "Airtel", "9482": "Airtel", "9483": "Airtel",
    "9484": "Airtel", "9485": "Airtel", "9486": "Airtel", "9487": "Airtel",
    "9488": "Airtel", "9489": "Airtel", "9490": "Airtel", "9491": "Airtel",
    "9492": "Airtel", "9493": "Airtel", "9494": "Airtel", "9495": "Airtel",
    "9496": "Airtel", "9497": "Airtel", "9498": "Airtel", "9499": "Airtel",
    "9500": "Airtel", "9501": "Airtel", "9502": "Airtel", "9503": "Airtel",
    "9504": "Airtel", "9505": "Airtel", "9506": "Airtel", "9507": "Airtel",
    "9508": "Airtel", "9509": "Airtel", "9510": "Airtel", "9511": "Airtel",
    "9512": "Airtel", "9513": "Airtel", "9514": "Airtel", "9515": "Airtel",
    "9516": "Airtel", "9517": "Airtel", "9518": "Airtel", "9519": "Airtel",
    "9520": "Airtel", "9521": "Airtel", "9522": "Airtel", "9523": "Airtel",
    "9524": "Airtel", "9525": "Airtel", "9526": "Airtel", "9527": "Airtel",
    "9528": "Airtel", "9529": "Airtel", "9530": "Airtel", "9531": "Airtel",
    "9532": "Airtel", "9533": "Airtel", "9534": "Airtel", "9535": "Airtel",
    "9536": "Airtel", "9537": "Airtel", "9538": "Airtel", "9539": "Airtel",
    "9540": "Airtel", "9541": "Airtel", "9542": "Airtel", "9543": "Airtel",
    "9544": "Airtel", "9545": "Airtel", "9546": "Airtel", "9547": "Airtel",
    "9548": "Airtel", "9549": "Airtel", "9550": "Airtel", "9551": "Airtel",
    "9552": "Airtel", "9553": "Airtel", "9554": "Airtel", "9555": "Airtel",
    "9556": "Airtel", "9557": "Airtel", "9558": "Airtel", "9559": "Airtel",
    "9560": "Airtel", "9561": "Airtel", "9562": "Airtel", "9563": "Airtel",
    "9564": "Airtel", "9565": "Airtel", "9566": "Airtel", "9567": "Airtel",
    "9568": "Airtel", "9569": "Airtel", "9570": "Airtel", "9571": "Airtel",
    "9572": "Airtel", "9573": "Airtel", "9574": "Airtel", "9575": "Airtel",
    "9576": "Airtel", "9577": "Airtel", "9578": "Airtel", "9579": "Airtel",
    "9580": "Airtel", "9581": "Airtel", "9582": "Airtel", "9583": "Airtel",
    "9584": "Airtel", "9585": "Airtel", "9586": "Airtel", "9587": "Airtel",
    "9588": "Airtel", "9589": "Airtel", "9590": "Airtel", "9591": "Airtel",
    "9592": "Airtel", "9593": "Airtel", "9594": "Airtel", "9595": "Airtel",
    "9596": "Airtel", "9597": "Airtel", "9598": "Airtel", "9599": "Airtel",
    "9600": "Airtel", "9601": "Airtel", "9602": "Airtel", "9603": "Airtel",
    "9604": "Airtel", "9605": "Airtel", "9606": "Airtel", "9607": "Airtel",
    "9608": "Airtel", "9609": "Airtel", "9610": "Airtel", "9611": "Airtel",
    "9612": "Airtel", "9613": "Airtel", "9614": "Airtel", "9615": "Airtel",
    "9616": "Airtel", "9617": "Airtel", "9618": "Airtel", "9619": "Airtel",
    "9620": "Airtel", "9621": "Airtel", "9622": "Airtel", "9623": "Airtel",
    "9624": "Airtel", "9625": "Airtel", "9626": "Airtel", "9627": "Airtel",
    "9628": "Airtel", "9629": "Airtel", "9630": "Airtel", "9631": "Airtel",
    "9632": "Airtel", "9633": "Airtel", "9634": "Airtel", "9635": "Airtel",
    "9636": "Airtel", "9637": "Airtel", "9638": "Airtel", "9639": "Airtel",
    "9640": "Airtel", "9641": "Airtel", "9642": "Airtel", "9643": "Airtel",
    "9644": "Airtel", "9645": "Airtel", "9646": "Airtel", "9647": "Airtel",
    "9648": "Airtel", "9649": "Airtel", "9650": "Airtel", "9651": "Airtel",
    "9652": "Airtel", "9653": "Airtel", "9654": "Airtel", "9655": "Airtel",
    "9656": "Airtel", "9657": "Airtel", "9658": "Airtel", "9659": "Airtel",
    "9660": "Airtel", "9661": "Airtel", "9662": "Airtel", "9663": "Airtel",
    "9664": "Airtel", "9665": "Airtel", "9666": "Airtel", "9667": "Airtel",
    "9668": "Airtel", "9669": "Airtel", "9670": "Airtel", "9671": "Airtel",
    "9672": "Airtel", "9673": "Airtel", "9674": "Airtel", "9675": "Airtel",
    "9676": "Airtel", "9677": "Airtel", "9678": "Airtel", "9679": "Airtel",
    "9680": "Airtel", "9681": "Airtel", "9682": "Airtel", "9683": "Airtel",
    "9684": "Airtel", "9685": "Airtel", "9686": "Airtel", "9687": "Airtel",
    "9688": "Airtel", "9689": "Airtel", "9690": "Airtel", "9691": "Airtel",
    "9692": "Airtel", "9693": "Airtel", "9694": "Airtel", "9695": "Airtel",
    "9696": "Airtel", "9697": "Airtel", "9698": "Airtel", "9699": "Airtel",
    "9700": "Airtel", "9701": "Airtel", "9702": "Airtel", "9703": "Airtel",
    "9704": "Airtel", "9705": "Airtel", "9706": "Airtel", "9707": "Airtel",
    "9708": "Airtel", "9709": "Airtel", "9710": "Airtel", "9711": "Airtel",
    "9712": "Airtel", "9713": "Airtel", "9714": "Airtel", "9715": "Airtel",
    "9716": "Airtel", "9717": "Airtel", "9718": "Airtel", "9719": "Airtel",
    "9720": "Airtel", "9721": "Airtel", "9722": "Airtel", "9723": "Airtel",
    "9724": "Airtel", "9725": "Airtel", "9726": "Airtel", "9727": "Airtel",
    "9728": "Airtel", "9729": "Airtel", "9730": "Airtel", "9731": "Airtel",
    "9732": "Airtel", "9733": "Airtel", "9734": "Airtel", "9735": "Airtel",
    "9736": "Airtel", "9737": "Airtel", "9738": "Airtel", "9739": "Airtel",
    "9740": "Airtel", "9741": "Airtel", "9742": "Airtel", "9743": "Airtel",
    "9744": "Airtel", "9745": "Airtel", "9746": "Airtel", "9747": "Airtel",
    "9748": "Airtel", "9749": "Airtel", "9750": "Airtel", "9751": "Airtel",
    "9752": "Airtel", "9753": "Airtel", "9754": "Airtel", "9755": "Airtel",
    "9756": "Airtel", "9757": "Airtel", "9758": "Airtel", "9759": "Airtel",
    "9760": "Airtel", "9761": "Airtel", "9762": "Airtel", "9763": "Airtel",
    "9764": "Airtel", "9765": "Airtel", "9766": "Airtel", "9767": "Airtel",
    "9768": "Airtel", "9769": "Airtel", "9770": "Airtel", "9771": "Airtel",
    "9772": "Airtel", "9773": "Airtel", "9774": "Airtel", "9775": "Airtel",
    "9776": "Airtel", "9777": "Airtel", "9778": "Airtel", "9779": "Airtel",
    "9780": "Airtel", "9781": "Airtel", "9782": "Airtel", "9783": "Airtel",
    "9784": "Airtel", "9785": "Airtel", "9786": "Airtel", "9787": "Airtel",
    "9788": "Airtel", "9789": "Airtel", "9790": "Airtel", "9791": "Airtel",
    "9792": "Airtel", "9793": "Airtel", "9794": "Airtel", "9795": "Airtel",
    "9796": "Airtel", "9797": "Airtel", "9798": "Airtel", "9799": "Airtel",
    "9800": "Airtel", "9801": "Airtel", "9802": "Airtel", "9803": "Airtel",
    "9804": "Airtel", "9805": "Airtel", "9806": "Airtel", "9807": "Airtel",
    "9808": "Airtel", "9809": "Airtel", "9810": "Airtel", "9811": "Airtel",
    "9812": "Airtel", "9813": "Airtel", "9814": "Airtel", "9815": "Airtel",
    "9816": "Airtel", "9817": "Airtel", "9818": "Airtel", "9819": "Airtel",
    "9820": "Airtel", "9821": "Airtel", "9822": "Airtel", "9823": "Airtel",
    "9824": "Airtel", "9825": "Airtel", "9826": "Airtel", "9827": "Airtel",
    "9828": "Airtel", "9829": "Airtel", "9830": "Airtel", "9831": "Airtel",
    "9832": "Airtel", "9833": "Airtel", "9834": "Airtel", "9835": "Airtel",
    "9836": "Airtel", "9837": "Airtel", "9838": "Airtel", "9839": "Airtel",
    "9840": "Airtel", "9841": "Airtel", "9842": "Airtel", "9843": "Airtel",
    "9844": "Airtel", "9845": "Airtel", "9846": "Airtel", "9847": "Airtel",
    "9848": "Airtel", "9849": "Airtel", "9850": "Airtel", "9851": "Airtel",
    "9852": "Airtel", "9853": "Airtel", "9854": "Airtel", "9855": "Airtel",
    "9856": "Airtel", "9857": "Airtel", "9858": "Airtel", "9859": "Airtel",
    "9860": "Airtel", "9861": "Airtel", "9862": "Airtel", "9863": "Airtel",
    "9864": "Airtel", "9865": "Airtel", "9866": "Airtel", "9867": "Airtel",
    "9868": "Airtel", "9869": "Airtel", "9870": "Airtel", "9871": "Airtel",
    "9872": "Airtel", "9873": "Airtel", "9874": "Airtel", "9875": "Airtel",
    "9876": "Airtel", "9877": "Airtel", "9878": "Airtel", "9879": "Airtel",
    "9880": "Airtel", "9881": "Airtel", "9882": "Airtel", "9883": "Airtel",
    "9884": "Airtel", "9885": "Airtel", "9886": "Airtel", "9887": "Airtel",
    "9888": "Airtel", "9889": "Airtel", "9890": "Airtel", "9891": "Airtel",
    "9892": "Airtel", "9893": "Airtel", "9894": "Airtel", "9895": "Airtel",
    "9896": "Airtel", "9897": "Airtel", "9898": "Airtel", "9899": "Airtel",
    # Vi (Vodafone Idea)
    "7040": "Vi (Vodafone Idea)", "7041": "Vi (Vodafone Idea)", "7042": "Vi (Vodafone Idea)",
    "7043": "Vi (Vodafone Idea)", "7044": "Vi (Vodafone Idea)", "7045": "Vi (Vodafone Idea)",
    "7046": "Vi (Vodafone Idea)", "7047": "Vi (Vodafone Idea)", "7048": "Vi (Vodafone Idea)",
    "7049": "Vi (Vodafone Idea)", "7350": "Vi (Vodafone Idea)", "7351": "Vi (Vodafone Idea)",
    "7352": "Vi (Vodafone Idea)", "7353": "Vi (Vodafone Idea)", "7354": "Vi (Vodafone Idea)",
    "7355": "Vi (Vodafone Idea)", "7356": "Vi (Vodafone Idea)", "7357": "Vi (Vodafone Idea)",
    "7358": "Vi (Vodafone Idea)", "7359": "Vi (Vodafone Idea)",
    "8700": "Vi (Vodafone Idea)", "8701": "Vi (Vodafone Idea)", "8702": "Vi (Vodafone Idea)",
    "8703": "Vi (Vodafone Idea)", "8704": "Vi (Vodafone Idea)", "8705": "Vi (Vodafone Idea)",
    "8706": "Vi (Vodafone Idea)", "8707": "Vi (Vodafone Idea)", "8708": "Vi (Vodafone Idea)",
    "8709": "Vi (Vodafone Idea)", "8710": "Vi (Vodafone Idea)", "8711": "Vi (Vodafone Idea)",
    "8712": "Vi (Vodafone Idea)", "8713": "Vi (Vodafone Idea)", "8714": "Vi (Vodafone Idea)",
    "8715": "Vi (Vodafone Idea)", "8716": "Vi (Vodafone Idea)", "8717": "Vi (Vodafone Idea)",
    "8718": "Vi (Vodafone Idea)", "8719": "Vi (Vodafone Idea)", "8720": "Vi (Vodafone Idea)",
    "8721": "Vi (Vodafone Idea)", "8722": "Vi (Vodafone Idea)", "8723": "Vi (Vodafone Idea)",
    "8724": "Vi (Vodafone Idea)", "8725": "Vi (Vodafone Idea)", "8726": "Vi (Vodafone Idea)",
    "8727": "Vi (Vodafone Idea)", "8728": "Vi (Vodafone Idea)", "8729": "Vi (Vodafone Idea)",
    "8730": "Vi (Vodafone Idea)", "8731": "Vi (Vodafone Idea)", "8732": "Vi (Vodafone Idea)",
    "8733": "Vi (Vodafone Idea)", "8734": "Vi (Vodafone Idea)", "8735": "Vi (Vodafone Idea)",
    "8736": "Vi (Vodafone Idea)", "8737": "Vi (Vodafone Idea)", "8738": "Vi (Vodafone Idea)",
    "8739": "Vi (Vodafone Idea)", "8740": "Vi (Vodafone Idea)", "8741": "Vi (Vodafone Idea)",
    "8742": "Vi (Vodafone Idea)", "8743": "Vi (Vodafone Idea)", "8744": "Vi (Vodafone Idea)",
    "8745": "Vi (Vodafone Idea)", "8746": "Vi (Vodafone Idea)", "8747": "Vi (Vodafone Idea)",
    "8748": "Vi (Vodafone Idea)", "8749": "Vi (Vodafone Idea)", "8750": "Vi (Vodafone Idea)",
    "8751": "Vi (Vodafone Idea)", "8752": "Vi (Vodafone Idea)", "8753": "Vi (Vodafone Idea)",
    "8754": "Vi (Vodafone Idea)", "8755": "Vi (Vodafone Idea)", "8756": "Vi (Vodafone Idea)",
    "8757": "Vi (Vodafone Idea)", "8758": "Vi (Vodafone Idea)", "8759": "Vi (Vodafone Idea)",
    "8760": "Vi (Vodafone Idea)", "8761": "Vi (Vodafone Idea)", "8762": "Vi (Vodafone Idea)",
    "8763": "Vi (Vodafone Idea)", "8764": "Vi (Vodafone Idea)", "8765": "Vi (Vodafone Idea)",
    "8766": "Vi (Vodafone Idea)", "8767": "Vi (Vodafone Idea)", "8768": "Vi (Vodafone Idea)",
    "8769": "Vi (Vodafone Idea)", "8770": "Vi (Vodafone Idea)", "8771": "Vi (Vodafone Idea)",
    "8772": "Vi (Vodafone Idea)", "8773": "Vi (Vodafone Idea)", "8774": "Vi (Vodafone Idea)",
    "8775": "Vi (Vodafone Idea)", "8776": "Vi (Vodafone Idea)", "8777": "Vi (Vodafone Idea)",
    "8778": "Vi (Vodafone Idea)", "8779": "Vi (Vodafone Idea)", "8780": "Vi (Vodafone Idea)",
    "8781": "Vi (Vodafone Idea)", "8782": "Vi (Vodafone Idea)", "8783": "Vi (Vodafone Idea)",
    "8784": "Vi (Vodafone Idea)", "8785": "Vi (Vodafone Idea)", "8786": "Vi (Vodafone Idea)",
    "8787": "Vi (Vodafone Idea)", "8788": "Vi (Vodafone Idea)", "8789": "Vi (Vodafone Idea)",
    "8790": "Vi (Vodafone Idea)", "8791": "Vi (Vodafone Idea)", "8792": "Vi (Vodafone Idea)",
    "8793": "Vi (Vodafone Idea)", "8794": "Vi (Vodafone Idea)", "8795": "Vi (Vodafone Idea)",
    "8796": "Vi (Vodafone Idea)", "8797": "Vi (Vodafone Idea)", "8798": "Vi (Vodafone Idea)",
    "8799": "Vi (Vodafone Idea)",
    "9800": "Vi (Vodafone Idea)", "9801": "Vi (Vodafone Idea)", "9802": "Vi (Vodafone Idea)",
    "9803": "Vi (Vodafone Idea)", "9804": "Vi (Vodafone Idea)", "9805": "Vi (Vodafone Idea)",
    "9806": "Vi (Vodafone Idea)", "9807": "Vi (Vodafone Idea)", "9808": "Vi (Vodafone Idea)",
    "9809": "Vi (Vodafone Idea)",
    "9900": "Vi (Vodafone Idea)", "9901": "Vi (Vodafone Idea)", "9902": "Vi (Vodafone Idea)",
    "9903": "Vi (Vodafone Idea)", "9904": "Vi (Vodafone Idea)", "9905": "Vi (Vodafone Idea)",
    "9906": "Vi (Vodafone Idea)", "9907": "Vi (Vodafone Idea)", "9908": "Vi (Vodafone Idea)",
    "9909": "Vi (Vodafone Idea)", "9910": "Vi (Vodafone Idea)", "9911": "Vi (Vodafone Idea)",
    "9912": "Vi (Vodafone Idea)", "9913": "Vi (Vodafone Idea)", "9914": "Vi (Vodafone Idea)",
    "9915": "Vi (Vodafone Idea)", "9916": "Vi (Vodafone Idea)", "9917": "Vi (Vodafone Idea)",
    "9918": "Vi (Vodafone Idea)", "9919": "Vi (Vodafone Idea)", "9920": "Vi (Vodafone Idea)",
    "9921": "Vi (Vodafone Idea)", "9922": "Vi (Vodafone Idea)", "9923": "Vi (Vodafone Idea)",
    "9924": "Vi (Vodafone Idea)", "9925": "Vi (Vodafone Idea)", "9926": "Vi (Vodafone Idea)",
    "9927": "Vi (Vodafone Idea)", "9928": "Vi (Vodafone Idea)", "9929": "Vi (Vodafone Idea)",
    "9930": "Vi (Vodafone Idea)", "9931": "Vi (Vodafone Idea)", "9932": "Vi (Vodafone Idea)",
    "9933": "Vi (Vodafone Idea)", "9934": "Vi (Vodafone Idea)", "9935": "Vi (Vodafone Idea)",
    "9936": "Vi (Vodafone Idea)", "9937": "Vi (Vodafone Idea)", "9938": "Vi (Vodafone Idea)",
    "9939": "Vi (Vodafone Idea)", "9940": "Vi (Vodafone Idea)", "9941": "Vi (Vodafone Idea)",
    "9942": "Vi (Vodafone Idea)", "9943": "Vi (Vodafone Idea)", "9944": "Vi (Vodafone Idea)",
    "9945": "Vi (Vodafone Idea)", "9946": "Vi (Vodafone Idea)", "9947": "Vi (Vodafone Idea)",
    "9948": "Vi (Vodafone Idea)", "9949": "Vi (Vodafone Idea)", "9950": "Vi (Vodafone Idea)",
    "9951": "Vi (Vodafone Idea)", "9952": "Vi (Vodafone Idea)", "9953": "Vi (Vodafone Idea)",
    "9954": "Vi (Vodafone Idea)", "9955": "Vi (Vodafone Idea)", "9956": "Vi (Vodafone Idea)",
    "9957": "Vi (Vodafone Idea)", "9958": "Vi (Vodafone Idea)", "9959": "Vi (Vodafone Idea)",
    "9960": "Vi (Vodafone Idea)", "9961": "Vi (Vodafone Idea)", "9962": "Vi (Vodafone Idea)",
    "9963": "Vi (Vodafone Idea)", "9964": "Vi (Vodafone Idea)", "9965": "Vi (Vodafone Idea)",
    "9966": "Vi (Vodafone Idea)", "9967": "Vi (Vodafone Idea)", "9968": "Vi (Vodafone Idea)",
    "9969": "Vi (Vodafone Idea)", "9970": "Vi (Vodafone Idea)", "9971": "Vi (Vodafone Idea)",
    "9972": "Vi (Vodafone Idea)", "9973": "Vi (Vodafone Idea)", "9974": "Vi (Vodafone Idea)",
    "9975": "Vi (Vodafone Idea)", "9976": "Vi (Vodafone Idea)", "9977": "Vi (Vodafone Idea)",
    "9978": "Vi (Vodafone Idea)", "9979": "Vi (Vodafone Idea)", "9980": "Vi (Vodafone Idea)",
    "9981": "Vi (Vodafone Idea)", "9982": "Vi (Vodafone Idea)", "9983": "Vi (Vodafone Idea)",
    "9984": "Vi (Vodafone Idea)", "9985": "Vi (Vodafone Idea)", "9986": "Vi (Vodafone Idea)",
    "9987": "Vi (Vodafone Idea)", "9988": "Vi (Vodafone Idea)", "9989": "Vi (Vodafone Idea)",
    "9990": "Vi (Vodafone Idea)", "9991": "Vi (Vodafone Idea)", "9992": "Vi (Vodafone Idea)",
    "9993": "Vi (Vodafone Idea)", "9994": "Vi (Vodafone Idea)", "9995": "Vi (Vodafone Idea)",
    "9996": "Vi (Vodafone Idea)", "9997": "Vi (Vodafone Idea)", "9998": "Vi (Vodafone Idea)",
    "9999": "Vi (Vodafone Idea)",
    # BSNL (Bharat Sanchar Nigam Limited)
    "9410": "BSNL", "9411": "BSNL", "9412": "BSNL", "9413": "BSNL",
    "9414": "BSNL", "9415": "BSNL", "9416": "BSNL", "9417": "BSNL",
    "9418": "BSNL", "9419": "BSNL", "9420": "BSNL", "9421": "BSNL",
    "9422": "BSNL", "9423": "BSNL", "9424": "BSNL", "9425": "BSNL",
    "9426": "BSNL", "9427": "BSNL", "9428": "BSNL", "9429": "BSNL",
    "9430": "BSNL", "9431": "BSNL", "9432": "BSNL", "9433": "BSNL",
    "9434": "BSNL", "9435": "BSNL", "9436": "BSNL", "9437": "BSNL",
    "9438": "BSNL", "9439": "BSNL", "9440": "BSNL", "9441": "BSNL",
    "9442": "BSNL", "9443": "BSNL", "9444": "BSNL", "9445": "BSNL",
    "9446": "BSNL", "9447": "BSNL", "9448": "BSNL", "9449": "BSNL",
    "9450": "BSNL", "9451": "BSNL", "9452": "BSNL", "9453": "BSNL",
    "9454": "BSNL", "9455": "BSNL", "9456": "BSNL", "9457": "BSNL",
    "9458": "BSNL", "9459": "BSNL", "9460": "BSNL", "9461": "BSNL",
    "9462": "BSNL", "9463": "BSNL", "9464": "BSNL", "9465": "BSNL",
    "9466": "BSNL", "9467": "BSNL", "9468": "BSNL", "9469": "BSNL",
    "9470": "BSNL", "9471": "BSNL", "9472": "BSNL", "9473": "BSNL",
    "9474": "BSNL", "9475": "BSNL", "9476": "BSNL", "9477": "BSNL",
    "9478": "BSNL", "9479": "BSNL", "9480": "BSNL", "9481": "BSNL",
    "9482": "BSNL", "9483": "BSNL", "9484": "BSNL", "9485": "BSNL",
    "9486": "BSNL", "9487": "BSNL", "9488": "BSNL", "9489": "BSNL",
    "9490": "BSNL", "9491": "BSNL", "9492": "BSNL", "9493": "BSNL",
    "9494": "BSNL", "9495": "BSNL", "9496": "BSNL", "9497": "BSNL",
    "9498": "BSNL", "9499": "BSNL",
}

# Indian telecom circles/states mapping (based on initial allocation, pre-MNP)
# These are approximate - MNP means users may have moved to different circles
INDIAN_CIRCLES = {
    # Andhra Pradesh & Telangana
    "9848": "Andhra Pradesh", "9849": "Andhra Pradesh", "9866": "Andhra Pradesh",
    "9885": "Andhra Pradesh", "9908": "Andhra Pradesh", "9912": "Andhra Pradesh",
    "9949": "Andhra Pradesh", "9989": "Andhra Pradesh",
    "7386": "Telangana", "7337": "Telangana", "7396": "Telangana",
    "9000": "Telangana", "9014": "Telangana", "9032": "Telangana",
    "9059": "Telangana", "9177": "Telangana", "9391": "Telangana",
    # Assam
    "9854": "Assam", "9864": "Assam", "9957": "Assam",
    "7002": "Assam", "7086": "Assam", "7578": "Assam",
    # Bihar & Jharkhand
    "9835": "Bihar", "9934": "Bihar", "9955": "Bihar",
    "7903": "Bihar", "7250": "Bihar", "7631": "Bihar",
    "9304": "Jharkhand", "9334": "Jharkhand", "9434": "Jharkhand",
    "7004": "Jharkhand", "7255": "Jharkhand", "7979": "Jharkhand",
    # Delhi NCR
    "9810": "Delhi NCR", "9811": "Delhi NCR", "9818": "Delhi NCR",
    "9871": "Delhi NCR", "9910": "Delhi NCR", "9911": "Delhi NCR",
    "9953": "Delhi NCR", "9958": "Delhi NCR",
    "7042": "Delhi NCR", "7065": "Delhi NCR", "7982": "Delhi NCR",
    # Gujarat
    "9825": "Gujarat", "9879": "Gujarat", "9898": "Gujarat",
    "7359": "Gujarat", "7383": "Gujarat", "7405": "Gujarat",
    "7574": "Gujarat", "7990": "Gujarat",
    # Haryana
    "9812": "Haryana", "9896": "Haryana", "9991": "Haryana",
    "7015": "Haryana", "7027": "Haryana", "7206": "Haryana",
    # Himachal Pradesh
    "9816": "Himachal Pradesh", "9817": "Himachal Pradesh",
    "7018": "Himachal Pradesh", "7807": "Himachal Pradesh",
    # Jammu & Kashmir
    "9419": "Jammu & Kashmir", "9469": "Jammu & Kashmir",
    "7006": "Jammu & Kashmir", "7051": "Jammu & Kashmir",
    # Karnataka
    "9845": "Karnataka", "9880": "Karnataka", "9972": "Karnataka",
    "7338": "Karnataka", "7349": "Karnataka", "7353": "Karnataka",
    "7411": "Karnataka", "7760": "Karnataka",
    # Kerala
    "9846": "Kerala", "9895": "Kerala", "9947": "Kerala",
    "7356": "Kerala", "7510": "Kerala", "7560": "Kerala",
    "7592": "Kerala", "7593": "Kerala",
    # Madhya Pradesh & Chhattisgarh
    "9893": "Madhya Pradesh", "9826": "Madhya Pradesh", "9827": "Madhya Pradesh",
    "7389": "Madhya Pradesh", "7354": "Madhya Pradesh", "7024": "Madhya Pradesh",
    "7771": "Chhattisgarh", "7879": "Chhattisgarh", "9301": "Chhattisgarh",
    # Maharashtra & Goa
    "9822": "Maharashtra", "9823": "Maharashtra", "9860": "Maharashtra",
    "7350": "Maharashtra", "7378": "Maharashtra", "7385": "Maharashtra",
    "7507": "Maharashtra", "7709": "Maharashtra",
    "9822": "Goa", "9823": "Goa",
    # Mumbai
    "9820": "Mumbai", "9821": "Mumbai", "9920": "Mumbai",
    "7045": "Mumbai", "7208": "Mumbai", "7710": "Mumbai",
    # North East (Arunachal Pradesh, Manipur, Meghalaya, Mizoram, Nagaland, Sikkim, Tripura)
    "9856": "North East", "9862": "North East",
    "7005": "North East", "7085": "North East",
    # Odisha
    "9937": "Odisha", "9938": "Odisha", "9437": "Odisha",
    "7008": "Odisha", "7077": "Odisha", "7328": "Odisha",
    # Punjab
    "9814": "Punjab", "9876": "Punjab", "9888": "Punjab",
    "7009": "Punjab", "7341": "Punjab", "7527": "Punjab",
    # Rajasthan
    "9828": "Rajasthan", "9829": "Rajasthan", "9799": "Rajasthan",
    "7014": "Rajasthan", "7023": "Rajasthan", "7062": "Rajasthan",
    # Tamil Nadu & Pondicherry
    "9840": "Tamil Nadu", "9841": "Tamil Nadu", "9884": "Tamil Nadu",
    "7200": "Tamil Nadu", "7339": "Tamil Nadu", "7358": "Tamil Nadu",
    "7373": "Tamil Nadu", "7397": "Tamil Nadu",
    # UP East (Lucknow, Varanasi, etc.)
    "9838": "UP East", "9918": "UP East", "9935": "UP East",
    "7235": "UP East", "7275": "UP East", "7309": "UP East",
    # UP West (Meerut, Noida, etc.)
    "9837": "UP West", "9917": "UP West", "9927": "UP West",
    "7017": "UP West", "7060": "UP West", "7310": "UP West",
    # West Bengal & Sikkim
    "9831": "West Bengal", "9832": "West Bengal", "9903": "West Bengal",
    "7439": "West Bengal", "7407": "West Bengal", "7278": "West Bengal",
    "7432": "Sikkim",
}


def normalize_phone(phone):
    """
    Normalize phone number by removing formatting characters.
    
    Removes spaces, dashes, parentheses, and dots.
    Preserves the leading + for international numbers.
    
    Args:
        phone: Phone number string
        
    Returns:
        Normalized phone number
    """
    # Keep the + if present, remove everything else non-digit
    cleaned = re.sub(r'[^\d+]', '', phone)
    return cleaned


def detect_format(phone):
    """
    Detect the format of a phone number.
    
    Returns format type and additional info.
    
    Args:
        phone: Phone number string
        
    Returns:
        Dict with format information
    """
    cleaned = normalize_phone(phone)
    digits = re.sub(r'[^\d]', '', phone)
    
    result = {
        "original": phone,
        "cleaned": cleaned,
        "digits": digits,
        "length": len(digits),
        "is_international": cleaned.startswith('+'),
        "format": "unknown",
        "country": "Unknown",
    }
    
    # Detect format based on length and prefix
    if result["is_international"]:
        result["format"] = "international"
        
        # Try to identify country code
        # Check 3-digit codes first, then 2-digit, then 1-digit
        # Country code starts at index 0 (after the + is removed from digits)
        for code_len in [3, 2, 1]:
            if len(digits) >= code_len:
                code = digits[:code_len]
                if code in COUNTRY_CODES:
                    result["country"] = COUNTRY_CODES[code]
                    result["country_code"] = f"+{code}"
                    break
    else:
        result["format"] = "national"
        
        # Detect by length
        if len(digits) == 10:
            result["format"] = "US/Canada (10-digit)"
        elif len(digits) == 11 and digits.startswith('1'):
            result["format"] = "US/Canada with country code"
        elif len(digits) == 11:
            result["format"] = "International (11-digit)"
    
    return result


def validate_phone(phone):
    """
    Validate phone number format.
    
    Checks:
    - Minimum length (7 digits)
    - Maximum length (15 digits per E.164)
    - Contains only valid characters
    
    Args:
        phone: Phone number string
        
    Returns:
        Tuple of (is_valid, reason)
    """
    cleaned = normalize_phone(phone)
    digits = re.sub(r'[^\d]', '', phone)
    
    if len(digits) < 7:
        return False, "Too short (minimum 7 digits)"
    
    if len(digits) > 15:
        return False, "Too long (maximum 15 digits per E.164)"
    
    if not re.match(r'^\+?[\d\s\-\(\)]{7,20}$', phone):
        return False, "Contains invalid characters"
    
    return True, "Valid"


def format_as_e164(phone):
    """
    Format phone number to E.164 format.
    
    E.164 format: +[country code][subscriber number]
    Example: +14155552671
    
    Args:
        phone: Phone number string
        
    Returns:
        E.164 formatted string
    """
    cleaned = normalize_phone(phone)
    
    if not cleaned.startswith('+'):
        # Assume US/Canada if no country code
        if len(cleaned) == 10:
            return f"+1{cleaned}"
        elif len(cleaned) == 11 and cleaned.startswith('1'):
            return f"+{cleaned}"
    
    return cleaned


def detect_carrier(phone):
    """
    Detect the mobile carrier/operator for Indian numbers.
    
    Uses the first 4 digits after +91 to identify the original carrier.
    Note: MNP (Mobile Number Portability) means users may have switched
    carriers while keeping their number. This shows the original allocation.
    
    Args:
        phone: Phone number string
        
    Returns:
        Tuple of (carrier_name, is_original) or (None, False)
    """
    cleaned = normalize_phone(phone)
    digits = re.sub(r'[^\d]', '', phone)
    
    # Only works for Indian numbers (country code 91)
    if not digits.startswith('91'):
        return None, False
    
    # Extract first 4 digits of subscriber number (after country code)
    subscriber = digits[2:]
    if len(subscriber) < 4:
        return None, False
    
    prefix = subscriber[:4]
    carrier = INDIAN_CARRIERS.get(prefix)
    
    if carrier:
        return carrier, True
    return None, False


def detect_telecom_circle(phone):
    """
    Detect the Indian telecom circle/state based on number allocation.
    
    Uses the first 4 digits after +91 to identify the original circle.
    Note: MNP means users may have moved to different circles.
    
    Args:
        phone: Phone number string
        
    Returns:
        Tuple of (circle_name, is_original) or (None, False)
    """
    cleaned = normalize_phone(phone)
    digits = re.sub(r'[^\d]', '', phone)
    
    # Only works for Indian numbers
    if not digits.startswith('91'):
        return None, False
    
    subscriber = digits[2:]
    if len(subscriber) < 4:
        return None, False
    
    prefix = subscriber[:4]
    circle = INDIAN_CIRCLES.get(prefix)
    
    if circle:
        return circle, True
    return None, False


def detect_number_type(phone):
    """
    Detect the type of phone number (mobile, landline, VoIP, toll-free).
    
    Classification logic (Indian numbers):
    - Mobile: 10 digits starting with 6-9
    - Landline: Starts with 0 + area code (2-4 digits) + 6-8 digit number
    - Toll-free: Starts with 1800, 1860, 1800
    - Premium: Starts with 123, 139, 1860
    - VoIP: Starts with 70, 80, 90 with specific patterns
    
    Args:
        phone: Phone number string
        
    Returns:
        String describing number type
    """
    digits = re.sub(r'[^\d]', '', phone)
    
    # Remove country code if present
    if digits.startswith('91') and len(digits) > 10:
        subscriber = digits[2:]
    elif digits.startswith('0'):
        subscriber = digits[1:]
    else:
        subscriber = digits
    
    # Toll-free numbers (India: 1800, 1860)
    if subscriber.startswith('1800') or subscriber.startswith('1860'):
        return "Toll-Free"
    
    # Premium rate numbers
    if subscriber.startswith('123') or subscriber.startswith('139'):
        return "Premium Rate"
    
    # Mobile numbers (India: 10 digits starting with 6-9)
    if len(subscriber) == 10 and subscriber[0] in '6789':
        return "Mobile"
    
    # Landline (with area code)
    if subscriber.startswith('0') and len(subscriber) >= 11:
        return "Landline (with area code)"
    
    # International format mobile
    if len(digits) == 12 and digits.startswith('91'):
        return "Mobile (International format)"
    
    # Short codes
    if len(subscriber) <= 5:
        return "Short Code"
    
    return "Unknown"


def search_phone_online(phone, verbose=False):
    """
    Search for a phone number using DuckDuckGo.
    
    Looks for public mentions, social media profiles, business listings,
    or any publicly available information tied to the number.
    
    Args:
        phone: Phone number string
        verbose: Enable verbose output
        
    Returns:
        List of search result dicts
    """
    results = []
    
    # Format the query - search with and without spaces
    digits = re.sub(r'[^\d]', '', phone)
    
    # Multiple search queries for better coverage
    queries = [
        f'"{phone}"',
        f'"{digits}"',
        f'"{phone}" site:facebook.com OR site:linkedin.com OR site:twitter.com',
    ]
    
    client = HTTPClient(rate_limit=2.0, timeout=15)
    
    try:
        for query in queries:
            if verbose:
                print(f"  {Colors.DIM}Searching: {query}{Colors.ENDC}")
            
            # DuckDuckGo HTML search (no API key needed)
            encoded_query = urllib.parse.quote(query)
            url = f"https://html.duckduckgo.com/html/?q={encoded_query}"
            
            response = client.get(url)
            if not response:
                continue
            
            # Parse the HTML response
            html = response.text
            
            # Extract result titles and snippets
            # Simple regex parsing (no bs4 dependency)
            title_pattern = r'<a[^>]*class="result__a"[^>]*>(.*?)</a>'
            snippet_pattern = r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>'
            url_pattern = r'<a[^>]*class="result__url"[^>]*>(.*?)</a>'
            
            titles = re.findall(title_pattern, html, re.DOTALL)
            snippets = re.findall(snippet_pattern, html, re.DOTALL)
            urls = re.findall(url_pattern, html, re.DOTALL)
            
            # Clean HTML tags
            def clean_html(text):
                text = re.sub(r'<[^>]+>', '', text)
                text = text.strip()
                return text
            
            for i in range(min(len(titles), 5)):  # Limit to top 5 results
                result = {
                    'title': clean_html(titles[i]) if i < len(titles) else '',
                    'snippet': clean_html(snippets[i]) if i < len(snippets) else '',
                    'url': clean_html(urls[i]) if i < len(urls) else '',
                    'query': query,
                }
                results.append(result)
            
            if verbose and results:
                print(f"  {Colors.DIM}Found {len(results)} results so far{Colors.ENDC}")
    
    finally:
        client.close()
    
    return results


def analyze_phone(phone, verbose=False):
    """
    Main function for phone number intelligence.
    
    Analyzes a phone number and provides:
    - Format detection
    - Country identification
    - Validation
    - E.164 normalization
    - Number type classification
    - Carrier/operator detection (Indian numbers)
    - Telecom circle/state lookup (Indian numbers)
    - Web search for public records
    
    Args:
        phone: Target phone number
        verbose: Enable verbose output
        
    Returns:
        Dict with phone intelligence
    """
    # Display header
    print(f"\n{Status.INFO} {Colors.BOLD}Phone Number Intelligence: {phone}{Colors.ENDC}\n")
    results = {}
    
    # Normalize the number
    cleaned = normalize_phone(phone)
    results['cleaned'] = cleaned
    
    # Validate
    is_valid, reason = validate_phone(phone)
    results['valid'] = is_valid
    results['validation_reason'] = reason
    
    if not is_valid:
        print(f"  {Status.ERROR} {Colors.FAIL}Invalid phone number: {reason}{Colors.ENDC}")
        return results
    
    # Detect format
    format_info = detect_format(phone)
    results['format'] = format_info
    
    print(f"  {Colors.CYAN}Format        :{Colors.ENDC} {format_info['format']}")
    print(f"  {Colors.CYAN}Length        :{Colors.ENDC} {format_info['length']} digits")
    print(f"  {Colors.CYAN}International :{Colors.ENDC} {'Yes' if format_info['is_international'] else 'No'}")
    
    if format_info.get('country') and format_info['country'] != 'Unknown':
        print(f"  {Colors.CYAN}Country       :{Colors.ENDC} {format_info['country']}")
        print(f"  {Colors.CYAN}Country Code  :{Colors.ENDC} {format_info.get('country_code', 'N/A')}")
    
    # Number type classification
    number_type = detect_number_type(phone)
    results['number_type'] = number_type
    print(f"  {Colors.CYAN}Type          :{Colors.ENDC} {number_type}")
    
    # E.164 format
    e164 = format_as_e164(phone)
    results['e164'] = e164
    print(f"\n  {Colors.CYAN}E.164 Format  :{Colors.ENDC} {e164}")
    
    print(f"  {Colors.CYAN}Raw Digits    :{Colors.ENDC} {format_info['digits']}")
    
    # Indian number specific analysis
    digits = re.sub(r'[^\d]', '', phone)
    if digits.startswith('91'):
        print(f"\n  {Colors.BOLD}--- Indian Mobile Analysis ---{Colors.ENDC}")
        
        # Carrier detection
        carrier, is_original = detect_carrier(phone)
        if carrier:
            results['carrier'] = carrier
            results['carrier_original'] = is_original
            print(f"  {Colors.CYAN}Carrier       :{Colors.ENDC} {carrier}")
            if not is_original:
                print(f"  {Colors.DIM}  (May have ported via MNP){Colors.ENDC}")
        else:
            print(f"  {Colors.CYAN}Carrier       :{Colors.ENDC} {Colors.DIM}Unknown (not in database){Colors.ENDC}")
        
        # Telecom circle detection
        circle, is_original_circle = detect_telecom_circle(phone)
        if circle:
            results['telecom_circle'] = circle
            results['circle_original'] = is_original_circle
            print(f"  {Colors.CYAN}Telecom Circle:{Colors.ENDC} {circle}")
            if not is_original_circle:
                print(f"  {Colors.DIM}  (May have ported to different circle){Colors.ENDC}")
        else:
            print(f"  {Colors.CYAN}Telecom Circle:{Colors.ENDC} {Colors.DIM}Unknown (not in database){Colors.ENDC}")
    
    # Web search
    print(f"\n  {Colors.BOLD}--- Web Search ---{Colors.ENDC}")
    print(f"  {Colors.CYAN}Searching for public records...{Colors.ENDC}")
    
    search_results = search_phone_online(phone, verbose)
    results['web_search'] = search_results
    
    if search_results:
        # Filter and display relevant results
        relevant = [r for r in search_results if phone in r.get('title', '') or phone in r.get('snippet', '')]
        
        if relevant:
            print(f"  {Status.FOUND} {Colors.OKGREEN}Found {len(relevant)} relevant result(s):{Colors.ENDC}")
            for i, result in enumerate(relevant[:5], 1):  # Show top 5
                print(f"\n  {Colors.BOLD}Result {i}:{Colors.ENDC}")
                if result.get('title'):
                    print(f"    {Colors.CYAN}Title:{Colors.ENDC} {result['title'][:80]}...")
                if result.get('snippet'):
                    print(f"    {Colors.CYAN}Info:{Colors.ENDC} {result['snippet'][:100]}...")
                if result.get('url'):
                    print(f"    {Colors.DIM}URL: {result['url']}{Colors.ENDC}")
        else:
            print(f"  {Status.INFO} {Colors.DIM}No directly matching results found{Colors.ENDC}")
            if verbose:
                print(f"  {Colors.DIM}Total results scanned: {len(search_results)}{Colors.ENDC}")
    else:
        print(f"  {Status.WARNING} {Colors.WARNING}Web search returned no results{Colors.ENDC}")
    
    if verbose:
        print(f"\n  {Colors.DIM}--- Additional Info ---{Colors.ENDC}")
        print(f"  {Colors.DIM}Original      : {phone}{Colors.ENDC}")
        print(f"  {Colors.DIM}Cleaned       : {cleaned}{Colors.ENDC}")
        print(f"  {Colors.DIM}All digits    : {format_info['digits']}{Colors.ENDC}")
    
    return results
