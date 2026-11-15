# Código DELIBERADAMENTE vulnerable para practicar con el analizador. No usar en producción.
import hashlib, pickle, subprocess, yaml, requests
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "hunter2-not-real"          # SEC001
app.config["DEBUG"] = True


def login(cursor, user, pwd):
    digest = hashlib.md5(pwd.encode()).hexdigest()                                   # CRY001
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user + " AND h = '" + digest + "'")  # INJ001


@app.route("/run")
def run():
    subprocess.run("ping " + request.args["host"], shell=True)                        # INJ003
    data = pickle.loads(request.data)                                                 # INJ004
    cfg = yaml.load(request.data)                                                     # INJ004
    return str(eval(request.args["expr"]))                                            # INJ002


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text                       # CRY002 / SSRF001


if __name__ == "__main__":
    app.run(debug=True)                                                               # CFG001
