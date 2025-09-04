import boto3
from cloud_auth_pkcs.aws.awscredentials import AWSCredentials


import argparse

parser = argparse.ArgumentParser(description='AWS auth using PKCS')
parser.add_argument("--module", default='/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')
parser.add_argument("--token", default='token1')
parser.add_argument("--label", default='keylabel5')
parser.add_argument("--pin", default='mynewpin')

parser.add_argument("--public_certificate_file",
                    default="certs/awsclient.crt")
parser.add_argument("--region", default="us-east-2")
parser.add_argument("--trust_anchor_arn",
                    default='', required=True)
parser.add_argument(
    "--role_arn", default="", required=True)
parser.add_argument(
    "--profile_arn", default="", required=True)

args = parser.parse_args()


pc = AWSCredentials(module=args.module,
                    token=args.token,
                    label=args.label,
                    pin=args.pin,

                    public_certificate_file=args.public_certificate_file,
                    region=args.region,
                    duration_seconds=1000,
                    trust_anchor_arn=args.trust_anchor_arn,
                    session_name="foo",
                    role_arn=args.role_arn,
                    profile_arn=args.profile_arn)


session = pc.get_session()

s3 = session.resource('s3')

for bucket in s3.buckets.all():
    print(bucket.name)
