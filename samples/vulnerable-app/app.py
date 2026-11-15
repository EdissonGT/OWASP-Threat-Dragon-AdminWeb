# DELIBERATELY vulnerable code to practice with the analyzer. Do not use in production.
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


def add_item(item, bucket=[]):                                                        # QLT009
    # TODO: validate item                                                             # QLT006
    try:
        bucket.append(item)
    except Exception:                                                                 # QLT005
        pass
    return bucket


def price(kind, qty, vip, coupon, country, weekend, bulk, gift):                      # QLT002 / QLT003
    total = 0
    if kind == "a":
        total = 10
    elif kind == "b":
        total = 20
    elif kind == "c":
        total = 30
    if qty > 10 and vip:
        total -= 1
    if coupon:
        total -= 2
    if country == "gt" or country == "sv":
        total += 1
    if weekend and not vip:
        total += 3
    if bulk:
        for i in range(qty):
            if i % 2 and gift:
                total -= 1
    while total < 0:
        total += 1
    return total if total else 1


if __name__ == "__main__":
    app.run(debug=True)                                                               # CFG001
