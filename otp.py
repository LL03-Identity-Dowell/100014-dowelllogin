import os
from twilio.rest import Client

# Set environment variables for your credentials
# Read more at http://twil.io/secure
account_sid = "ACa5a6a5642592ffdcb45f0147a2bb314c"
auth_token = "35c7e6aab8603f6c32713a2e24d724cc"
verify_sid = "VA8411895db4aaed9f0c7477371e4981b4"
client = Client(account_sid, auth_token)
def mobilnumber(verified_number):
    verification = client.verify.v2.services(verify_sid) \
      .verifications \
      .create(to=verified_number, channel="sms")
    return verification.status
def mobilotp(verified_number,otp_code):
    verification_check = client.verify.v2.services(verify_sid) \
      .verification_checks \
      .create(to=verified_number, code=otp_code)
    return verification_check.status