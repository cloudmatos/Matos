#!/usr/bin/exec python3

from flask import Flask
from flask_cors import CORS
from flasgger import Swagger
from api.route.home import home_api
from api.route.resource import resource_api


def create_app():
    app = Flask(__name__)

    app.config['SWAGGER'] = {
        'title': 'Matos API Starter Kit',
    }
    swagger = Swagger(app)
    CORS(app)

     ## Initialize Config
    app.config.from_pyfile('config.py')
    app.register_blueprint(home_api, url_prefix='/api')
    app.register_blueprint(resource_api, url_prefix='/resources')

    return app


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app = create_app()
    app.run(host='0.0.0.0', port=port,debug=True)
