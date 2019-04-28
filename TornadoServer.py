import subprocess
import sys

import tornado.ioloop
import tornado
import tornado.web
import tornado.gen
import tornado.httpserver
import tornado.escape
import tornado.websocket
import json
import bcrypt
import motor.motor_tornado
import pymongo
import requests

import os
import ssl
import datetime
import random
from concurrent.futures import ThreadPoolExecutor
from tornado import options

executor = ThreadPoolExecutor(8)  # declare 8 threads


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("SERVER REST API")


"""
POST /user/login
Function to handle login process, json format:
    {
        "email": String,
        "password": String
    }
"""
class LogInHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header("Access-Control-Allow-Headers", "access-control-allow-origin,authorization,content-type")

    def options(self):
        self.set_status(204)
        self.finish()

    def get(self):
        pass

    # Function to handle HTTP POST Request for Log in from Client side
    async def post(self):

        data = json.loads(self.request.body)                                       # Get body of POST request
        username = data["email"]
        password = data["password"]
        print("SIGNIN REQ: " + str(data))
        executor.submit(await self.check(username, password))

    async def check(self, username, password):
        try:
            client = motor.motor_tornado.MotorClient('mongodb://localhost:27017')   # Connect to MongoDB Server
            db = client.mobappex                                                    # Get database mobappex
            document = await db.users.find_one({"username": username})              # Search username DB
            if document is not None:                                                # Found matching user in DB
                print(document)
                salt = document["salt"]                                             # Get user's salt from DB
                hashed_pass = bcrypt.hashpw(password.encode("utf8"), salt)          # Hash input password with salt

                if hashed_pass == document["password"]:                             # Input password matches
                    json_response = {
                        "status": 'success',
                        "user": {
                            "name": document["name"],
                            "matriculationNumber": document["matriculation_number"],
                            "email": document["username"]
                        }
                    }
                    self.write(json.dumps(json_response))
                    self.set_header('Content-Type', 'application/json')
                    print(json_response)
                    self.finish()

                else:                                                               # Input password wrong
                    self.response_fail("no-match")
            else:                                                                   # User doesn't exist
                self.response_fail("user-not-existed")
        except:
            print("error")

    def response_fail(self, reason):
        json_response = {
            "status": "fail",
            "reason": reason
        }
        self.write(json.dumps(json_response))
        self.set_header('Content-Type', 'application/json')
        print(json_response)
        self.finish()


"""
POST /user/signup
Function to handle sign up request, json format: 
{
    "title": String
    "firstName": String
    "lastName": String
    "matriculationNumber": String
    "email": String
    "password": String
    
}
"""
class SignUpHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header("Access-Control-Allow-Headers", "access-control-allow-origin,authorization,content-type")

    def options(self):
        self.set_status(204)
        self.finish()

    def get(self):
        print("get")

    # Function to handle HTTP POST Request for Sign up from client
    async def post(self):
        data = json.loads(self.request.body)                                            # Get body of POST request
        print("SIGNUP REQ: " + str(data))
        executor.submit(await self.check(data))

    async def check(self, data):
        title = data["title"]
        first_name = data["firstName"]
        last_name = data["lastName"]
        matriculation_number = data["matriculationNumber"]
        username = data["email"]
        password = data["password"]

        # Check for email domain
        domain_splits = username.split("@")                                            # Split the email
        if "fra-uas.de" not in domain_splits[1]:                                       # Checks if domain is correct
            self.response_fail("not-university-domain")

        # Check for existing username in database
        else:
            client = motor.motor_tornado.MotorClient('mongodb://localhost:27017')      # Connect to MongoDB server
            db = client.mobappex                                                       # Get database mobappex
            document = await db.users.find_one({"username": username})                 # Checks DB for username
            if document is not None:                                                   # Username already existed
                print(document)
                self.response_fail("user-existed")

            # Create new user
            else:                                                                      # Username is available
                salt = bcrypt.gensalt()                                                # Generate a random salt
                hashed_pass = bcrypt.hashpw(password.encode("utf8"), salt)             # Hash the password with salt
                new_user = await db.users.insert_one({"_id": username,
                                                      "username": username,
                                                      "password": hashed_pass,
                                                      "salt": salt,
                                                      "name": {
                                                          "title": title,
                                                          "last_name": last_name,
                                                          "first_name": first_name
                                                      },
                                                      "matriculation_number": matriculation_number,
                                                      "type": "user",
                                                      })
                json_response = {
                    "status": "success"
                }
                self.write(json.dumps(json_response))
                self.set_header('Content-Type', 'application/json')
                print(json_response)
                self.finish()

    def response_fail(self, reason):
        json_response = {
            "status": "fail",
            "reason": reason
        }
        self.write(json.dumps(json_response))
        self.set_header('Content-Type', 'application/json')
        print(json_response)
        self.finish()


"""
POST /user/activate
Endpoint to handle request for activating an user account, json format:
{
    "username": String,
    "balance": number
}
"""
class UserActivateHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header("Access-Control-Allow-Headers", "access-control-allow-origin,authorization,content-type")

    def options(self):
        self.set_status(204)
        self.finish()

    def get(self):
        pass

    async def post(self):
        status = "fail"
        data = json.loads(self.request.body)
        print(data)
        username = data["username"]
        balance = data["balance"]
        client = motor.motor_tornado.MotorClient('mongodb://localhost:27017')           # Connect to MongoDB server
        db = client.mobappex
        document = await db.users.find_one({"username": username})
        if document is not None:
            status = "OK"
            update_transaction = db.users.update_one(
                {"username": username},
                {"$set": {"status": "active"}})
            update_transaction = db.users.update_one(
                {"username": username},
                {"$set": {"balance": balance}})
        json_response = {
            "status": status
        }
        print(json_response)
        self.write(json.dumps(json_response))
        self.set_header('Content-Type', 'application/json')
        self.finish()


class Application(tornado.web.Application):
    def __init__(self):

        handlers = [
            (r"/", MainHandler),
            (r"/user/login", LogInHandler),
            (r"/user/signup", SignUpHandler),
            # Add more paths here
        ]

        settings = {
            "debug": True,
        }

        tornado.web.Application.__init__(self, handlers, **settings)


if __name__ == "__main__":
    tornado.options.parse_command_line()
    app = Application()
    location = os.path.join(os.getcwd(), "certs")
    #ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    #ssl_ctx.load_cert_chain(os.path.join(location, "server.crt"),
    #                        os.path.join(location, "server.key"))
    #server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
    server = tornado.httpserver.HTTPServer(app)
    server.listen(8888)
    print("REST API Server started on: https://localhost:8888")
    tornado.ioloop.IOLoop.current().start()