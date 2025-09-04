from google.cloud import storage
from cloud_auth_pkcs.gcp.gcpcredentials import GCPCredentials

import argparse

parser = argparse.ArgumentParser(description='GCP Auth using PKCS')

parser.add_argument("--module", default='/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')
parser.add_argument("--token", default='token1')
parser.add_argument("--label", default='keylabel3')
parser.add_argument("--pin", default='mynewpin')

parser.add_argument("--email", default='', required=True)
parser.add_argument("--project_id", default='', required=True)
parser.add_argument("--key_id", default='', required=False)
parser.add_argument("--bucket", default='', required=False)

args = parser.parse_args()

pc = GCPCredentials(module=args.module,
                    token=args.token,
                    label=args.label,
                    pin=args.pin,
                    key_id=args.key_id,
                    email=args.email)

storage_client = storage.Client(project=args.project_id, credentials=pc)

objects = storage_client.list_blobs(args.bucket)
for o in objects:
    print(o.name)
