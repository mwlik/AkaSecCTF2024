from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/comment', methods=['POST'])
def calculate():
    comment = request.form.get('comment')
    if not comment:
        return 'No comment provided', 400
    return subprocess.check_output('echo "A really simple command that needs a comment to explain it" # ' + comment, shell=True)