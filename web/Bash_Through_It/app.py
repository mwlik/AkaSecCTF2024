from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/comment', methods=['POST'])
def calculate():
    comment = request.form.get('comment')
    if not comment:
        return 'No comment provided', 400
    comment = comment.replace('flag.txt', '')
    comment = comment.replace('*', '')
    try:
        output = subprocess.check_output('echo "A really simple echo that needs a comment to explain it" # ' + comment, shell=True)
    except subprocess.CalledProcessError as e:
        return 'Error', 500
    return 'Comment added successfully!', 200
    

if __name__ == '__main__':
    app.run(debug=True)