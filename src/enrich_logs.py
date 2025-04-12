import pandas as pd
from enrich_JSON_logs import enrich_JSON_logs
import requests
from logenrichment_functions import return_raw_string
from enrich_CSV_logs import enrich_CSV_logs

print("Loading in configuration files")
#Read in script configuration df
script_config_df=pd.read_csv('')
#Read in fields that will be enriched
field_to_enrich_df=pd.read_csv(return_raw_string(script_config_df[script_config_df['Type']=='Path_to_Field_Configuration_File']['setting_value'].to_list()[0]))
#Read in the logs that will be enriched
print("Configuration files loaded successfully")

print("Loading in API Secrets")
#Load in API keys required for IP enrichment
    #API keys are required for log enrichment becaise API requests are made to Virus Total, ipInfo, IPAbuseDB, and IPQS
vt_api_key=script_config_df[script_config_df['Type']=='VT_API_Key']['setting_value'].to_list()[0]
ip_info_api_key=script_config_df[script_config_df['Type']=='IP_Info_API_Key']['setting_value'].to_list()[0]
ip_AbuseDB_API_Key=script_config_df[script_config_df['Type']=='IP_Abuse_DB_API_Key']['setting_value'].to_list()[0]
ipqs_API_key=script_config_df[script_config_df['Type']=='IPQS_API_Key']['setting_value'].to_list()[0]

#Load in Entra ID Client, Entra ID secret, and Tenant ID fields
    #Entra Client ID, Entra Client secret, and Entra Tenant ID fields are required for account enrichment because Ent/Users/josephbrennan/githubProjects/open_source_log_enrichment_tool/src/enrich_logs.pyra ID directory is quiered for log enrichment
client_id=script_config_df[script_config_df['Type']=='Entra_Client_ID']['setting_value'].to_list()[0]
client_secret=script_config_df[script_config_df['Type']=='Entra_Client_Secret']['setting_value'].to_list()[0]
tenant_ID=script_config_df[script_config_df['Type']=='Tenant_ID']['setting_value'].to_list()[0]
print("API Secrets loaded successfully")

print("Requesting OAuth Bearer token for MS Graph API")
#Perform POST request to retrieve Bearer Token for GraphAPI GET requests
request_for_oauth_Token_headers={"client_id":client_id,"client_secret":client_secret,"resource":"https://graph.microsoft.com","grant_type":"client_credentials"}
bearer_token_for_graph_api_requests=requests.post(url=f"https://login.microsoftonline.com/{tenant_ID}/oauth2/token",data=request_for_oauth_Token_headers).json().get('access_token')
print("OAuth Bearer Token obtained successfully")
#Perform Graph API GET request to obtain list of all enabled users with your Entra ID Tenant
print("Requesting list of enabled accounts within the cloud directory")
list_of_enabled_accounts_with_fields_to_enrich_on=requests.get(url="https://graph.microsoft.com/v1.0/users",headers={"authorization":f"Bearer {bearer_token_for_graph_api_requests}"},params={"$filter":"accountEnabled eq true","$select":f"mailNickname,Userprincipalname,firstName,lastName,userType,companyName,department,employeeeId,officelocation,mail,mailNickname,Lastpasswordchangedatetime,Createddatetime,jobtitle,employeeId,officeLocation,state,postalCode,country"}).json().get('value')
print("List of enabled accounts obtained successfully")
#Create dictionary of private IP and Bogon IP Ranges
dictionary_of_Private_IP_Ranges_And_Bogons={"10.0.0.0/8":["IPv4","Private","Reserved Private IPv4 Address Range"],"192.168.0.0/16":["IPv4","Private","Reserved Private IPv4 Address Range"],"172.16.0.0/12":["IPv4","Private","Reserved Private IPv4 Address Range"], "0.0.0.0/8":["IPv4","Private","Bogon: This Network"],"100.64.0.0/10":["IPv4","Public","Bogon: Carrier-grade NAT"],"127.0.0.0/8":["IPv4","Private","Bogon: Loopback Range"],"127.0.53.53":["IPv4","Public","Bogon: Name collision occurrence"],"169.254.0.0/16":["IPv4","Public","Bogon: Link local"],"192.0.0.0/24":["IPv4","Public","Bogon: IETF protocol assignments"],"192.0.2.0/24":["IPv4","Public","Bogon: TEST-NET-1"],"198.18.0.0/15":["IPv4","Public","Bogon: Network interconnect device benchmark testing"],"198.51.100.0/24":["IPv4","Public","Bogon: TEST-NET-2"]
,"203.0.113.0/24":["IPv4","Public","Bogon: TEST-NET-3"],"224.0.0.0/4":["IPv4","Private","Bogon: Multicast"],"240.0.0.0/4":["IPv4","Public","Bogon: Reserved for future use"],"255.255.255.255/32":["IPv4","Private","Broadcast address"],"::/128".upper():["IPv6","Private","Node-scope unicast unspecified address"],"::1/128".upper():["IPv6","Private","Node-scope unicast loopback address"],"::ffff:0:0/96".upper():["IPv6","Public","Bogon: IPv4-mapped addresses"],"::/96".upper():["IPv6","Public","Bogon: IPv4-compatible addresses"],"100::/64".upper():["IPv6","Public","Bogon: Remotely triggered black hole addresses"],"2001:10::/28".upper():["IPv6","Public","Bogon: Overlay routable cryptographic hash identifiers (ORCHID)"],"2001:db8::/32".upper():["IPv6","Public","Bogon: Documentation prefix"],"3fff::/20".upper():["IPv6","Public","Bogon: Documentation prefix"],"fc00::/7".upper():["IPv6","Private","Unique local addresses (ULA)"],"fe80::/10".upper():["IPv6","Private","Link-local unicast"],"fec0::/10".upper():["IPv6","Private","Site-local unicast"],"ff00::/8".upper():["IPv6","Private","Multicast"]
,"2002::/24".upper():["IPv6","Private","6to4 bogon (0.0.0.0/8)"],"2002:a00::/24".upper():["IPv6","Private","6to4 bogon (10.0.0.0/8)"],"2002:7f00::/24".upper():["IPv6","Private","6to4 bogon (127.0.0.0/8)"],"2002:a9fe::/32".upper():["IPv6","Private","6to4 bogon (169.254.0.0/16)"],"2002:ac10::/28".upper():["IPv6","Private","6to4 bogon (172.16.0.0/12)"],"2002:c000::/40".upper():["IPv6","Public","Bogon: 6to4 bogon (192.0.0.0/24)"],"2002:c000:200::/40".upper():["IPv6","Public","Bogon: 6to4 bogon (192.0.2.0/24)"],"2002:c0a8::/32".upper():["IPv6","Private","6to4 bogon (192.168.0.0/16)"],"2002:c612::/31".upper():["IPv6","Public","Bogon: 6to4 bogon (198.18.0.0/15)"],"2002:c633:6400::/40".upper():["IPv6","Public","Bogon: 6to4 bogon (198.51.100.0/24)"],"2002:cb00:7100::/40".upper():["IPv6","Public","Bogon: 6to4 bogon (203.0.113.0/24)"],"2002:e000::/20".upper():["IPv6","Private","6to4 bogon (224.0.0.0/4)"],
"2002:f000::/20".upper():['IPv6',"Public","Bogon: 6to4 bogon (240.0.0.0/4)"],"2002:ffff:ffff::/48".upper():["IPv6","Private","6to4 bogon (255.255.255.255/32)"],"2001::/40".upper():["IPv6","Private","Teredo bogon (0.0.0.0/8)"],"2001:0:a00::/40".upper():["IPv6","Private","Teredo bogon (10.0.0.0/8)"],"2001:0:7f00::/40".upper():["IPv6","Private","Teredo bogon (127.0.0.0/8)"],"2001:0:a9fe::/48".upper():["IPv6","Private","Teredo bogon (169.254.0.0/16)"],"2001:0:ac10::/44".upper():["IPv6","Private","Teredo bogon (172.16.0.0/12)"],"2001:0:c000::/56".upper():["IPv6","Public","Bogon: Teredo bogon (192.0.0.0/24)"],"2001:0:c000:200::/56".upper():["IPv6","Public","Bogon: Teredo bogon (192.0.2.0/24)"],"2001:0:c0a8::/48".upper():["IPv6","Private","Teredo bogon (192.168.0.0/16)"],"2001:0:c612::/47".upper():["IPv6","Public","Bogon: Teredo bogon (198.18.0.0/15)"],"2001:0:c633:6400::/56".upper():["IPv6","Public","Bogon: Teredo bogon (198.51.100.0/24)"],"2001:0:cb00:7100::/56".upper():["IPv6","Public","Bogon: Teredo bogon (203.0.113.0/24)"],"2001:0:e000::/36".upper():["IPv6","Private","Teredo bogon (224.0.0.0/4)"],"2001:0:f000::/36".upper():["IPv6","Public","Bogon: Teredo bogon (240.0.0.0/4)"],"2001:0:ffff:ffff::/64".upper():["IPv6","Private","Teredo bogon (255.255.255.255/32)"]}

print("Attempting to determine the log file format")
#Enriching JSON logs
if script_config_df[script_config_df['Type']=='Input_File_Format']['setting_value'].to_list()[0].upper()=='JSON':
    print("Enriching JSON logs")
    enrich_JSON_logs(return_raw_string(script_config_df[script_config_df['Type']=='Path_to_Log_File_To_Enrich']['setting_value'].to_list()[0]),field_to_enrich_df['field_name'].to_list(),field_to_enrich_df,dictionary_of_Private_IP_Ranges_And_Bogons,vt_api_key,ip_info_api_key,ip_AbuseDB_API_Key,ipqs_API_key,list_of_enabled_accounts_with_fields_to_enrich_on,bearer_token_for_graph_api_requests,script_config_df)
elif script_config_df[script_config_df['Type']=='Input_File_Format']['setting_value'].to_list()[0].upper()=='CSV':
    print("Enriching CSV logs")
    enrich_CSV_logs(pd.read_csv(return_raw_string(script_config_df[script_config_df['Type']=='Path_to_Log_File_To_Enrich']['setting_value'].to_list()[0])),field_to_enrich_df,dictionary_of_Private_IP_Ranges_And_Bogons,vt_api_key,ip_info_api_key,ip_AbuseDB_API_Key,ipqs_API_key,list_of_enabled_accounts_with_fields_to_enrich_on,bearer_token_for_graph_api_requests,script_config_df)
