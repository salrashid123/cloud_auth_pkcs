import boto3
from cloud_auth_pkcs.aws.awshmaccredentials import AWSHMACCredentials

import argparse

parser = argparse.ArgumentParser(description='AWS HMAC Auth using PKCS')

parser.add_argument("--module", default='/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')
parser.add_argument("--token", default='token1')
parser.add_argument("--label", default='keylabel4')
parser.add_argument("--pin", default='mynewpin')

parser.add_argument("--aws_access_key_id", default='', required=True)
parser.add_argument("--region", default="us-east-1", required=True)

parser.add_argument("--get_session_token", default=False)

parser.add_argument(
    "--assume_role_arn", default="", required=True)
parser.add_argument(
    "--role_session_name", default="foo", required=False)

args = parser.parse_args()



import pkcs11

PKCS_LIB = '/usr/lib/softhsm/libsofthsm2.so'
PIN = 'mynewpin'

pc = AWSHMACCredentials(
    module=args.module,
    token=args.token,
    label=args.label,
    pin=args.pin,

    access_key=args.aws_access_key_id,
    region=args.region,
    duration_seconds=3600,
    role_session_name=args.role_session_name,
    assume_role_arn=args.assume_role_arn,

    get_session_token=args.get_session_token,
)

session = pc.get_session()

s3 = session.resource('s3')

for bucket in s3.buckets.all():
    print(bucket.name)
