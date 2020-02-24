import sys
import json
import requests
import boto3
import uuid
import base64
import ast

from awsglue.utils import getResolvedOptions


args = getResolvedOptions(sys.argv,
                          ['SALESFORCE_URL',
                            'SECRET_NAME',
                           'REGION_NAME',
                           'OUTPUT_BUCKET_NAME',
                           'OBJECT_LIST'])

# Get Secret Information 

session = boto3.session.Session()
client = session.client(
    service_name='secretsmanager',
    region_name=args['REGION_NAME']
)

try:
    get_secret_value_response = client.get_secret_value(
        SecretId=args['SECRET_NAME']
    )
except ClientError as e:
    raise e
    quit()
else:
    secret = get_secret_value_response['SecretString']
    secrets = ast.literal_eval(secret)


# Get a bearer token

LOGIN_URL = "https://login.salesforce.com/services/oauth2/token"
LOGIN_PARAMS = {'grant_type':'password', 'client_id': secrets["CLIENT_ID"], 'client_secret': secrets["CLIENT_SECRET"], 'username': secrets["USERNAME"], 'password': secrets["PASSWORD"]} 

tokenResponse = requests.post(url = LOGIN_URL, params = LOGIN_PARAMS)
if not tokenResponse.ok:
    print(tokenResponse.json())
    quit()

TOKEN = tokenResponse.json()["access_token"]

print("Backup started")


for object in args['OBJECT_LIST'].split(","):
    
    print("Processing object " + object)
    
    #call object describe
    
    describeUrl = args['SALESFORCE_URL'] + "/sobjects/"+ object +"/describe"
    describeResponse = requests.get(url = describeUrl, headers={'Authorization': 'Bearer %s' % TOKEN}) 
    if not describeResponse.ok:
        print(describeResponse.json())
        quit()

    selectFields=[]
    for field in describeResponse.json()['fields']:
        selectFields.append(field['name'])

    selectText = ','.join(selectFields)
    
 
    #call query on object with all fields
 
    queryUrl = args['SALESFORCE_URL'] + "/query"

    params = {'q':'SELECT '+ selectText + ' from ' + object} 

    queryResponse = requests.get(url = queryUrl, params = params, headers={'Authorization': 'Bearer %s' % TOKEN}) 


    # prepare query results
    if not queryResponse.ok:
        print(queryResponse.json())
        quit()
    
    data = queryResponse.json()
    resultObject={}
    resultObject={ 'Object Name': object, 'Object Count': data["totalSize"], 'Records': data["records"]}
    
    # save results to s3 bucket
    
    s3 = boto3.resource('s3')
    fileName = 'backup-{}-{}.json'.format(object, uuid.uuid4())
    s3object = s3.Object(args['OUTPUT_BUCKET_NAME'], fileName)

    s3object.put(
        Body=(bytes(json.dumps(resultObject).encode('UTF-8')))
    )

    print('Saved backup with name: {} to S3 bucket {}'.format(fileName, args['OUTPUT_BUCKET_NAME']))


print('Backup job finished succesfully')
