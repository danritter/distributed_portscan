import json

class PortScanResultParser:


    def parse_nmap_results(self, data):
        results = {}
        for host in data['nmaprun']['host']:
            if type(host['ports']['port']) == list:
                for port in host['ports']['port']:
                    if port['state']['@state'] == 'open':
                        if host['address']['@addr'] not in results:
                            results[host['address']['@addr']] = []
                        results[host['address']['@addr']].append(port['@portid'])
            else:
                if host['ports']['port']['state']['@state'] == 'open':
                    results[host['address']['@addr']] = [host['ports']['port']['@portid']]

        return results

    def parse_masscan_results(self,data):
        results = {}
        for result in data:
            if result['ports'][0]['status'] == 'open':
                if result['ip'] not in results:
                    results[result['ip']] = []
                results[result['ip']].append(result['ports'][0]['port'])

        return results




if __name__ ==  "__main__":
    data = json.load(open('../data/cloud_formation/outputs/nmap_out.json'))
    print(NmapParser().parse_nmap_results(data))