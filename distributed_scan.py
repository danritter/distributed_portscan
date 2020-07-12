#!flask/bin/python
from flask import Flask, jsonify, request
import random
import re
import os
import string
import subprocess
import json

app = Flask(__name__)

def validate_ports(ports):
    for port in ports:
        if validate_port(port) == False:
            return False
    return True

def validate_port(port):
    return type(port) == int


@app.route('/scan', methods=['POST'])
def port_scans():

    content = request.get_json(silent=True)
    
    if 'secret' not in content or content['secret'] != '':
        return jsonify({'error':'bad_secret'})

    fn = 'masscan_{0}.json'.format(''.join(random.choice(string.ascii_letters) for i in range(8)))
    command = "masscan "

    if 'host' in content:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", content['host']) == None:   
            return jsonify({'error':'bad_host'})
        else:
            command += content['host']  

    elif 'cidr' in content:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", content['cidr']) == None:
            return jsonify({'error':'bad_cidr'})
        else:
            command += content['cidr']
    else:
        return jsonify({'error':'missing_hosts'})

    command += ' -p '

    if 'start_port' in content and 'end_port' in content:
        if validate_port(content['start_port']) == False or validate_port(content['end_port']) == False:
            return jsonify({'error':'bad_port'})
        else:
            command += '{0}-{1}'.format(content['start_port'],content['end_port'])
    elif 'ports' in content:
        if validate_ports(content['ports']) == False:
            return jsonify({'error':'bad_port'})
        else:
            command += ','.join([str(i) for i in content['ports']])
    else:
        return jsonify({'error':'missing_ports'})

    command += ' -oJ {0} --rate=100'.format(fn)

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    process.wait()
    results = open(fn,'r').read()
    os.remove(fn)
    if results != '':
        try:
            return(jsonify(json.loads(results[:-4] + ']')))
        except:
            return(jsonify({'error':"bad_results_json"}))

    else: 
       return jsonify({})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
