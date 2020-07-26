#!flask/bin/python
from flask import Flask, jsonify, request
import random
import os
import string
import subprocess
import json
import validator
import xmltodict
import parser

app = Flask(__name__)
validator = validator.Validator()
parser = parser.PortScanResultParser()

@app.route('/masscan', methods=['POST'])
def masscan():

    try:
        if os.path.exists('masscan.lock'):
            return jsonify({"error": "Scan already running"})
        else:
            os.system('touch masscan.lock')

        content = request.get_json(silent=True)

        valid = validator.validate_request(content)
        if valid is not None:
            os.remove('masscan.lock')
            return valid

        fn = 'masscan_{0}.json'.format(''.join(random.choice(string.ascii_letters) for i in range(8)))
        command = "masscan "

        if 'host' in content:
            command += content['host']
        else:
            command += content['cidr']

        command += ' -p '

        if 'start_port' in content and 'end_port' in content:
            command += '{0}-{1}'.format(content['start_port'], content['end_port'])
        else:
            command += ','.join([str(i) for i in content['ports']])

        command += ' -oJ {0} --rate=100'.format(fn)

        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        process.wait()
        results = open(fn, 'r').read()
        os.remove(fn)
        json_data = json.loads(results[:-4] + ']')

        if results != '':
            try:
                os.remove('masscan.lock')
                return (jsonify(parser.parse_masscan_results(json_data)))
            except:
                os.remove('masscan.lock')
                return (jsonify({'error': "bad_results_json"}))

        else:
            return jsonify({})

    except Exception as e:
        os.remove('nmap.lock')
        return jsonify({"error": e})


@app.route('/nmap', methods=['POST'])
def nmap():

    try:
        if os.path.exists('nmap.lock'):
            return jsonify({"error": "Scan already running"})
        else:
            os.system('touch nmap.lock')

        content = request.get_json(silent=True)

        valid = validator.validate_request(content)
        if valid is not None:
            os.remove('nmap.lock')
            return valid

        fn = 'nmap_{0}.xml'.format(''.join(random.choice(string.ascii_letters) for i in range(8)))
        command = "nmap "

        if 'host' in content:
            command += content['host']
        else:
            command += content['cidr']

        command += ' -p '

        if 'start_port' in content and 'end_port' in content:
            command += '{0}-{1}'.format(content['start_port'], content['end_port'])
        else:
            command += ','.join([str(i) for i in content['ports']])

        command += ' -oX {0} -T3 -Pn'.format(fn)

        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        process.wait()
        results = open(fn, 'r').read()
        os.remove(fn)
        if results != '':
            try:
                return (jsonify(parser.parse_nmap_results(xmltodict.parse(results))))
            except:
                os.remove('nmap.lock')
                return (jsonify({'error': "bad_results_json"}))

        else:
            os.remove('nmap.lock')
            return jsonify({})

    except Exception as e:
        os.remove('nmap.lock')
        return jsonify({"error":e})


@app.route('/status', methods=['GET'])
def get_status(self):
    return jsonify({'masscan': True, 'nmap': True})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
