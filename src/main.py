import ipgetter
import requests
import argparse
import sys
import pprint


class CloudflareAccount:
    def __init__(self, email, access_key, domain):
        self.email = email
        self.access_key = access_key
        self.domain = domain
        self.zone_id = None
        self.dns_record_id = None
        self.API_ENDPOINT = "https://api.cloudflare.com/client/v4"

    def set_zone_id(self, zone_id):
        self.zone_id = zone_id

    def set_dns_record_id(self, dns_record_id):
        self.dns_record_id = dns_record_id

    def get_zone_id(self):
        return self.zone_id

    def get_dns_record_id(self):
        return self.dns_record_id

    def get_email(self):
        return self.email

    def get_access_key(self):
        return self.access_key

    def get_auth_header(self):
        return {"X-Auth-Key": self.access_key, "X-Auth-Email": self.email}

    def get_api_endpoint(self):
        return self.API_ENDPOINT

    def get_domain(self):
        return self.domain

    @staticmethod
    def get_ipv4():
        return ipgetter.myip()


def parse_args(args):
    parser = argparse.ArgumentParser()
    req_args = parser.add_argument_group(title='required')
    req_args.add_argument("-e", "--email", required="True", metavar="Email", type=str,
                          help="Specify Cloudflare email account.")
    req_args.add_argument("-k", "--accessKey", required="True", metavar="AccessKey", type=str,
                          help="Specify Cloudflare API access key.")
    req_args.add_argument("-d", "--domain", metavar="DomainName", type=str, required="True",
                          help="Enter your domain name without www.")

    args = parser.parse_args(args)
    return args


def list_zones(account):
    headers = account.get_auth_header()
    headers["Content-Type"] = 'application/json'
    response = requests.get(
        account.get_api_endpoint() + '/zones?name=' + account.get_domain() + '&status=active&match=all',
        headers=headers)
    response.raise_for_status()
    json_response = response.json()
    if len(json_response['result']) == 0:
        raise EnvironmentError('Domain name not found')
    account.set_zone_id(str(json_response['result'][0]['id']))
    return account


def list_dns_record(account):  # TODO: Consider IPV6 option
    headers = account.get_auth_header()
    headers["Content-Type"] = 'application/json'
    response = requests.get(
        account.get_api_endpoint() + '/zones/' + account.get_zone_id() + '/dns_records',
        headers=headers)
    response.raise_for_status()
    json_response = response.json()
    if len(json_response['result']) == 0:
        raise EnvironmentError('No DNS record found in the ZoneID: ' + account.get_zone_id())
    for record in json_response['result']:
        if record['type'] == 'A':
            if record['name'] == account.get_domain():
                account.set_dns_record_id(str(record['id']))
                return account
    raise EnvironmentError('IPV4/Type A IP not found in this domain ' + account.get_domain())


def update_dns_record(account):
    headers = account.get_auth_header()
    headers["Content-Type"] = 'application/json'
    data = {"type": "A", "name": account.get_domain(), "content": account.get_ipv4()}
    response = requests.put(
        account.get_api_endpoint() + '/zones/' + account.get_zone_id() + '/dns_records/' + account.get_dns_record_id(),
        headers=headers, json=data)
    response.raise_for_status()

    return response.json()["result"]


def main(args):
    cloudflare_account = CloudflareAccount(args.email, args.accessKey, args.domain)
    try:
        list_zones(cloudflare_account)
        list_dns_record(cloudflare_account)
        return update_dns_record(cloudflare_account)
    except requests.exceptions.HTTPError as e:
        if "404" in str(e):
            print >> sys.stderr, "API endpoint not found"
        elif "400" in str(e):
            print >> sys.stderr, "Bad request"
        elif "403" in str(e):
            print >> sys.stderr, "Invalid Email or AccessKey"
        sys.exit(2)
    except EnvironmentError as e:
        print >> sys.stderr, str(e)
        sys.exit(2)
    except requests.exceptions.Timeout as e:
        print >> sys.stderr, str(e)
        sys.exit(2)


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    result = main(args)
    pprint.pprint(result)
