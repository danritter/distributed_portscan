from flask import  jsonify
import re

class Validator:

    def validate_ports(self, ports):
        for port in ports:
            if self.validate_port(port) == False:
                return False
        return True


    def validate_port(self, port):
        return type(port) == int and 1 <= port <= 65535


    def validate_request(self, content):
        if 'secret' not in content or content['secret'] != '':
            return jsonify({'error': 'bad_secret'})

        if 'host' in content:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", content['host']) == None:
                return jsonify({'error': 'bad_host'})

        elif 'cidr' in content:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", content['cidr']) == None:
                return jsonify({'error': 'bad_cidr'})

        else:
            return jsonify({'error': 'missing_hosts'})

        if 'start_port' in content and 'end_port' in content:
            if self.validate_port(content['start_port']) == False or self.validate_port(content['end_port']) == False:
                return jsonify({'error': 'bad_port'})
        elif 'ports' in content:
            if self.validate_ports(content['ports']) == False:
                return jsonify({'error': 'bad_port'})
        else:
            return jsonify({'error': 'missing_ports'})

        return None