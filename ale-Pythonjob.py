import sys
import json
import requests
import boto3
import uuid
import base64
import ast
from botocore.exceptions import ClientError

from awsglue.utils import getResolvedOptions


args = getResolvedOptions(sys.argv,
                          ['SECRET_NAME',
                           'REGION_NAME',
                           'OUTPUT_BUCKET_NAME'])

# Create a Secrets Manager client
session = boto3.session.Session()
client = session.client(
    service_name='secretsmanager',
    region_name=args['REGION_NAME']
)

# Get secrets

try:
    get_secret_value_response = client.get_secret_value(
        SecretId=args['SECRET_NAME']
    )
except ClientError as e:
    raise e
else:
    secret = get_secret_value_response['SecretString']
    secrets = ast.literal_eval(secret)


#Get bearer token
LOGIN_URL = "https://login.salesforce.com/services/oauth2/token"
LOGIN_PARAMS = {'grant_type':'password', 'client_id': secrets["CLIENT_ID"], 'client_secret': secrets["CLIENT_SECRET"], 'username': secrets["USERNAME"], 'password': secrets["PASSWORD"]} 

tokenResponse = requests.post(url = LOGIN_URL, params = LOGIN_PARAMS)
if not tokenResponse.ok:
    print(tokenResponse.json())
    quit()

TOKEN = tokenResponse.json()["access_token"]
 
URL = "https://s3-backup.my.salesforce.com/services/data/v20.0/query"
PARAMS = {'q':'SELECT name,type from Account'} 
response = requests.get(url = URL, params = PARAMS, headers={'Authorization': 'Bearer %s' % TOKEN}) 
  
# extracting data in json format 
if not response.ok:
    print(response.json())
    quit()
    
    
data = response.json()
results = []


for result in data["records"]:
    if result["Type"] is not None:
        accountInfo ={}
        accountInfo["Name"] = result["Name"]
        accountInfo["Type"] = result["Type"]
        results.append(accountInfo)
    
s3 = boto3.resource('s3')
fileName = 'backup{}.json'.format(uuid.uuid4())
s3object = s3.Object(args['OUTPUT_BUCKET_NAME'], fileName)

s3object.put(
    Body=(bytes(json.dumps(results).encode('UTF-8')))
)

print('Saved file with name: {} to S3 bucket {}'.format(fileName, args['OUTPUT_BUCKET_NAME']))


