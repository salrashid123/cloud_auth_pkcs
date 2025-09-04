from azure.storage.blob import BlobServiceClient
from cloud_auth_pkcs.azure.azurecredentials import AzureCredentials

import argparse

parser = argparse.ArgumentParser(description='Azure auth using PKCS')

parser.add_argument("--module", default='/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')
parser.add_argument("--token", default='token1')
parser.add_argument("--label", default='keylabel6')
parser.add_argument("--pin", default='mynewpin')

parser.add_argument("--certificate_path",
                    default="certs/azure.crt", required=True)
parser.add_argument(
    "--tenant_id", default="", required=True)
parser.add_argument(
    "--client_id", default="", required=True)
parser.add_argument("--storageaccount", default="", required=True)
parser.add_argument("--container", default="", required=True)

args = parser.parse_args()


pc = AzureCredentials(
    module=args.module,
    token=args.token,
    label=args.label,
    pin=args.pin,

    tenant_id=args.tenant_id,
    client_id=args.client_id,
    certificate_path=args.certificate_path)

blob_service_client = BlobServiceClient(
    account_url="https://{}.blob.core.windows.net".format(args.storageaccount),
    credential=pc
)
container_client = blob_service_client.get_container_client(args.container)

blob_list = container_client.list_blobs()
for blob in blob_list:
    print(blob.name)
