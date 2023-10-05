import logging
import sys
import datetime
import certstream
import queue
import threading

'''
{
    "message_type": "certificate_update",
    "data": {
        "update_type": "X509LogEntry",
        "leaf_cert": {
            "subject": {
                "aggregated": "/CN=app.theaffairsite.com",
                "C": null,
                "ST": null,
                "L": null,
                "O": null,
                "OU": null,
                "CN": "app.theaffairsite.com"
            },
            "extensions": {
                "keyUsage": "Digital Signature, Key Encipherment",
                "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
                "basicConstraints": "CA:FALSE",
                "subjectKeyIdentifier": "01:BE:17:27:B8:D8:26:EF:E1:5C:7A:F6:14:A7:EA:B5:D0:D8:B5:9B",
                "authorityKeyIdentifier": "keyid:A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1\n",
                "authorityInfoAccess": "OCSP - URI:http://ocsp.int-x3.letsencrypt.org\nCA Issuers - URI:http://cert.int-x3.letsencrypt.org/\n",
                "subjectAltName": "DNS:app.theaffairsite.com",
                "certificatePolicies": "Policy: 2.23.140.1.2.1\nPolicy: 1.3.6.1.4.1.44947.1.1.1\n  CPS: http://cps.letsencrypt.org\n  User Notice:\n    Explicit Text: This Certificate may only be relied upon by Relying Parties and only in accordance with the Certificate Policy found at https://letsencrypt.org/repository/\n"
            },
            "not_before": 1509908649.0,
            "not_after": 1517684649.0,
            "serial_number": "33980d1bef9b6a76cfc708e3139f55f33c5",
            "fingerprint": "95:CA:86:6B:B4:98:59:D2:EC:C7:CA:E8:42:70:80:0B:18:03:C7:75",
            "as_der": "MIIFDTCCA/WgAwIBAgISAzmA0b75tqds/HCOMTn1XzPFMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQDExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNzExMDUxOTA0MDlaFw0xODAyMDMxOTA0MDlaMCAxHjAcBgNVBAMTFWFwcC50aGVhZmZhaXJzaXRlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtVFBtTDAMq5yt/fRujvt3XbxjAb58NG6ThmXiFN/rDyysKt4tsqYcOQRZc5D/z4Pm8hI3lgLgmiZdxJF6zUnJ7GoYGdpPwItmYHmp1rWo735NNw16zFMKw9KPi1l+aiKQqZQA9hcgXpbWoyoIZBwHS5K5Id6/uXfLk//9nRxaKqDQzB1ZokIzlv0u+hJxKA4Q+JyOiZvfQKDBcC9lEXsNJ74MTkCwu75qjvHYHB4jSrb3aiCxn7q934bI+CFFjCK1adyGJVnckXOcumZrPo4c8GL0Fc1uwZ/PdLvU9/4d/PpbSHdaN94B3bVxCjio/KnSJ8QNJo60QoEOZ60aCFN0CAwEAAaOCAhUwggIRMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUAb4XJ7jYJu/hXHr2FKfqtdDYtZswHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUHAQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5cHQub3JnLzAgBgNVHREEGTAXghVhcHAudGhlYWZmYWlyc2l0ZS5jb20wgf4GA1UdIASB9jCB8zAIBgZngQwBAgEwgeYGCysGAQQBgt8TAQEBMIHWMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRpZmljYXRlIG1heSBvbmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGllcyBhbmQgb25seSBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIENlcnRpZmljYXRlIFBvbGljeSBmb3VuZCBhdCBodHRwczovL2xldHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEASpYg0ISnbyXpqYYzgpLdc8o6GZwKrMDrTARm63aT+2L88s2Ff6JlMz4XRH3v4iihLpLVUDoiXbNUyggyVqbkQLFtHtgj8ScLvWku8n7l7lp6DpV7j3h6byM2K6a+jasJKplL+Zbqzng0RaJlFFnnBXYE9a5BW3JlOzNbOMUOSKTZSB0+6pmeohU1DhNiPQNqT2katRu0LLGbwtcEpsWyScVc3VkJVu1l0QNq8gC+F3C2MpBtiSjjz6umP1F1z+sXhUx9dFVzJ2nSk7XxZaH+DW4OAb6zjwqqYjjf2S0VQM398URhfYzLQX6xEyDuZG4W58g5SMtOWDnslPhlIax3LA==",
            "all_domains": [
                "app.theaffairsite.com"
            ]
        },
        "cert_index": 27910635,
        "seen": 1509912803.959279,
        "source": {
            "url": "sabre.ct.comodo.com",
            "name": "Comodo 'Sabre' CT log"
        }
    }
}
'''


class Certfeed:
    
    def __init__(self, domains_queue: queue.Queue, domains_dict: dict):
        print("Certfeed init")
        self.domains_queue = domains_queue
        self.domains_dict = domains_dict
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
        threading.Thread(target=self.start_certstream).start()
        
    def start_certstream(self):
        certstream.listen_for_events(self.get_callback, url='wss://certstream.calidog.io/')
      
    def get_callback(self, message, context):
        logging.debug("Message -> {}".format(message))

        if message['message_type'] == "certificate_update":
            all_domains = message['data']['leaf_cert']['all_domains']

            if len(all_domains) == 0:
                domain = "NULL"
            else:
                domain = all_domains[0]
            self.domains_dict[domain] = message['data']
            self.domains_queue.put(domain)



