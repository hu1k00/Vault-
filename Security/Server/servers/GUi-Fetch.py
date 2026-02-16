from flask import Flask, request, render_template_string
import requests
import os

app = Flask(__name__)

KALI_SERVER = "http://192.168.26.139:5090"  # change to your Kali IP

HTML = """
<!doctype html>
<html>
<head><title>File Fetcher</title></head>
<body>
<h2>Fetch File From Kali</h2>
<form method="POST">
    <input type="text" name="filename" placeholder="Enter filename">
    <input type="submit" value="Fetch">
</form>
<p>{{ message }}</p>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    if request.method == "POST":
        filename = request.form["filename"]
        try:
            r = requests.get(f"{KALI_SERVER}/{filename}")
            if r.status_code == 200:
                with open(filename, "wb") as f:
                    f.write(r.content)
                message = f"File '{filename}' downloaded successfully."
            else:
                message = "File not found on Kali server."
        except:
            message = "Connection error."
    return render_template_string(HTML, message=message)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
