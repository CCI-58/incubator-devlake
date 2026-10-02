#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Exercise only the disposable CI image/database, including backend restart."""
import hashlib
import hmac
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

NAME = "cci-devlake-image-smoke"
BASE = "http://127.0.0.1:18080"
KEY = "ci-only-source-control-secret-32-bytes"
OPERATION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def request(method, path, expected, body=None, owner=False, control=False):
    headers = {"Content-Type": "application/json"}
    if control:
        headers["X-CCI-Control-Key"] = KEY
    if owner:
        headers["X-CCI-Source-Token"] = hmac.new(
            KEY.encode(), ("cci-source-control-v1:" + OPERATION).encode(), hashlib.sha256
        ).hexdigest()
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status, payload = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, payload = error.code, error.read()
    if status != expected:
        raise RuntimeError(f"{method} {path}: expected {expected}, got {status}")
    return json.loads(payload) if payload else None


def ready():
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            request("GET", "/ready", 200)
            return
        except (OSError, RuntimeError):
            time.sleep(3)
    raise RuntimeError("CI DevLake did not become ready")


def verify_held():
    state = request("GET", "/cci/source-control/" + OPERATION, 200, control=True)
    assert state == {"protocol": 1, "operation": OPERATION, "blueprints": [], "held": True}, state
    request("GET", "/proceed-db-migration", 409)
    request("GET", "/proceed-db-migration", 200, owner=True)


def main():
    image = os.environ["TEST_IMAGE"]
    revision = os.environ["TEST_REVISION"]
    subprocess.run([
        "docker", "run", "--detach", "--name", NAME, "--network", "host",
        "--env", "DB_URL=mysql://merico:ci-isolated-db@127.0.0.1:3306/lake?charset=utf8mb4&parseTime=True&loc=UTC",
        "--env", "PORT=18080", "--env", "MODE=release",
        "--env", "FORCE_MIGRATION=true", "--env", "DISABLED_REMOTE_PLUGINS=true",
        "--env", "ENCRYPTION_SECRET=0123456789abcdef0123456789abcdef",
        "--env", "CCI_SOURCE_CONTROL_KEY=" + KEY, image,
    ], check=True, stdout=subprocess.DEVNULL)
    try:
        ready()
        version = request("GET", "/version", 200)
        if revision not in json.dumps(version):
            raise RuntimeError("Built image does not report its source revision")
        request("POST", "/cci/source-control", 403, {"operation": OPERATION, "blueprints": []})
        request("POST", "/cci/source-control", 200, {"operation": OPERATION, "blueprints": []}, control=True)
        verify_held()
        subprocess.run(["docker", "restart", NAME], check=True, stdout=subprocess.DEVNULL)
        ready()
        verify_held()
        request("DELETE", "/cci/source-control/" + OPERATION, 204, control=True)
        request("GET", "/proceed-db-migration", 200)
        request("GET", "/proceed-db-migration", 409, owner=True)
        print("Built image: source revision, persistent fence, restart and release verified.")
    finally:
        subprocess.run(["docker", "rm", "--force", NAME], check=False, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
