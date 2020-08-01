import config
import requests
import hmac
from hashlib import sha256
import xml.etree.ElementTree as ET


# Define vars
## TODO : Replace these vars with your own credentials

SFR_BOX_IP = config.ip_address
SFR_USERNAME = config.username
SFR_PASSWORD = config.password


def box_login():
    """Connect to SFR box via API with passwd method and collect token

    Returns:
        login_cookie: token to connect box via API
    """
    # Hash login and password
    auth_hash_value = sha256(f"{SFR_USERNAME}:{SFR_PASSWORD}".encode("utf-8")).hexdigest()
    auth_hash_value = auth_hash_value.encode()

    # Generate API request and collect response
    response_xml_raw = requests.get(f"http://{SFR_BOX_IP}/api/1.0/?method=auth.getToken")
    response_xml = response_xml_raw.text

    # Parse XML tree to get passowrd
    tree = ET.fromstring(response_xml)
    for item in tree:
        # if request return code is 200 and response contains auth value
        if response_xml_raw.ok and item.tag == "auth":
            token = item.attrib["token"]
            login_cookie = hmac.new(token, auth_hash_value, sha256).digest()
        # Error case
        else:
            login_cookie = "-1"
    return login_cookie


if __name__ == "__main__":
    cookie = box_login()
    # Collect ONT informations
    print(requests.get(f"http://{SFR_BOX_IP}/api/1.0/?method=ont.getInfo").text)

    # Collect WAN informations
    print(requests.get(f"http://{SFR_BOX_IP}/api/1.0/?method=wan.getInfo").text)
    
    # Collect System informations
    print(requests.get(f"http://{SFR_BOX_IP}/api/1.0/?method=system.getInfo").text)

    # Call history
    print(requests.get(f"http://{SFR_BOX_IP}/api/1.0/?method=voip.getCallhistoryList&token={cookie}").text)