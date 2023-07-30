from flask import Flask, render_template, request, g, jsonify, session, redirect, url_for, send_from_directory, send_file, flash
import pymysql
import whois
import datetime
import subprocess

app = Flask(__name__)

# Database configuration
DB_HOST = 'localhost'
DB_USER = 'panel'
DB_PASSWORD = 'NewPassword'
DB_NAME = 'panel'

# Function to check the API key against the database and update request count
def validate_api_key(api_key):
    try:
        connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        with connection.cursor() as cursor:
            # Check if the API key exists in the database
            sql = "SELECT COUNT(*) FROM api_users WHERE api_key = %s"
            cursor.execute(sql, (api_key,))
            result = cursor.fetchone()
            if result[0] > 0:
                # Increment the request count for the user
                sql = "UPDATE api_users SET requests = requests + 1 WHERE api_key = %s"
                cursor.execute(sql, (api_key,))
                connection.commit()
                return True
            else:
                return False
    except pymysql.Error as e:
        print("Error: ", e)
        return False
    finally:
        connection.close()

# Function to store the request information in a file
def store_request_in_file(route, api_key, domain=None, ip=None):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('requests.txt', 'a') as file:
        if domain:
            file.write(f"Route: {route}, Domain: {domain}, API Key: {api_key}, Date: {timestamp}\n")
        elif ip:
            file.write(f"Route: {route}, IP: {ip}, API Key: {api_key}, Date: {timestamp}\n")
        else:
            file.write(f"Route: {route}, API Key: {api_key}, Date: {timestamp}\n")


# DOMAIN WHOIS INFO
@app.route('/whois/<domain>')
def get_whois(domain):
    api_key = request.headers.get('Authorization')

    if not api_key:
        return jsonify({'error': 'API Key missing'}), 401

    if not validate_api_key(api_key):
        return jsonify({'error': 'Invalid API Key'}), 401

    # If the API key is valid, store the request in the file
    store_request_in_file('/whois', api_key, domain=domain)
    try:
        # Perform WHOIS lookup using the python-whois library
        whois_result = whois.whois(domain)

        # Check if the domain exists in WHOIS data
        if whois_result.domain_name:
            # Extract relevant information from the WHOIS data
            data = {
                'domain_name': whois_result.domain_name,
                'registrar': whois_result.registrar,
                'creation_date': whois_result.creation_date.strftime('%Y-%m-%d %H:%M:%S') if whois_result.creation_date else None,
                'expiration_date': whois_result.expiration_date.strftime('%Y-%m-%d %H:%M:%S') if whois_result.expiration_date else None,
                'name_servers': whois_result.name_servers,
                'status': whois_result.status,
                'dnssec': whois_result.dnssec,
                'last_update': whois_result.last_updated.strftime('%Y-%m-%d %H:%M:%S') if whois_result.last_updated else None,
                'update_date': whois_result.updated_date[0].strftime('%Y-%m-%d %H:%M:%S') if whois_result.updated_date else None,
            }

            # Add the raw WHOIS data to the response
            data['whois_raw_data'] = whois_result.text

            return jsonify(data), 200
        else:
            return jsonify({'error': 'Domain not found in WHOIS data'}), 404

    except whois.exceptions.UnknownTld as e:
        return jsonify({'error': 'Unknown top-level domain'}), 400
    except Exception as e:
        return jsonify({'error': 'Error occurred during WHOIS lookup'}), 500


# GEOIPLOCATION
@app.route('/geolocation/<ip>')
def get_geolocation(ip):
    api_key = request.headers.get('Authorization')
    
    if not api_key:
        return jsonify({'error': 'API Key missing'}), 401

    if validate_api_key(api_key):
        store_request_in_file('/geolocation', api_key, ip=ip)
        try:
            # Perform geolocation lookup using the existing code
            result = subprocess.check_output(['geoiplookup', ip]).decode('utf-8')
            # Extract the geolocation data from the result (modify this based on your output)
            country = result.split(':')[1].strip()
            return jsonify({'ip': ip, 'country': country})
        except subprocess.CalledProcessError:
            return jsonify({'error': 'Invalid IP address'}), 400
    else:
        return jsonify({'error': 'Invalid API Key'}), 401


# HOME PAGE
@app.route('/')
def home():
    return render_template('dashboard.html')

# DASH
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


# LOGOUT LINK
@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
