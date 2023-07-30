from flask import Flask, jsonify, request
import pymysql

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


@app.route('/geolocation/<ip>')
def get_geolocation(ip):
    api_key = request.headers.get('Authorization')
    
    if not api_key:
        return jsonify({'error': 'API Key missing'}), 401

    if validate_api_key(api_key):
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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
