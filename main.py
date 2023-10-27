from settings import token, authToken, legalEntityUrl, dataFolder
import uuid, time, jwt, json, time, csv, os.path, requests

session = None
error_count = 0

#izgūst tokenu
def getToken():
	print('Izgūstu tokenu')
	global authToken
	header = {
		"typ" : "JWT",
		"alg" : "RS256",
		"x5c" : token['publicKey']
	};
	claimSet = {
		"sub": token['clientId'],
		"jti": str(uuid.uuid4()),
		"iss": token['clientId'],
		"aud": token['audience'],
		"exp": str(int(time.time()) + 3600),
		"nbf": str(int(time.time())), 
		}
	jwtToken = jwt.encode(claimSet, token['privateKey'], algorithm='RS256', headers = header)
	data = {
		'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
		'client_assertion': jwtToken,
		'grant_type': 'client_credentials',
		'client_id': token['clientId'],
		'client_secret': token['clientSecret']
	}
	r = requests.post(
			token['url'],
			data = data,
			headers = {
				'Content-Type': 'application/x-www-form-urlencoded'	
			}
		)
	if r.status_code == 200 and 'access_token' in r.json():
		authToken = r.json()['access_token']
		print('Tokens izgūts')
	else:
		print('Nevieksmīgs tokena pieprasījums')
		print(r.status_code)
		print(r.text)

#izgūst LegalEntity datus
def getLegalEntity(regno, history = False, count = 0):
	global error_count
	headers = {
		'Accept': 'application/json',
		'Content-Type': 'application/json',
		'Authorization': 'Bearer ' + authToken
	}
	url = legalEntityUrl + str(regno) + ('/history' if history else '')
	r = session.get(
			url,
			headers = headers
		)
	if r.status_code == 200:
		with open('data/' + regno +'.json', 'wb') as f:
			f.write(r.content)
	else:
		error_count += 1
		print("%s: %s" % (r.status_code, r.text))
		if error_count > 50: 
			print("Sasniegts kļūdu limits")
			return False
	if r.status_code == 401:
		print("%s: %s" % (r.status_code, r.text))
		time.sleep(5)
		if headers['Authorization'] == 'Bearer ' + authToken:
			getToken()
		if count > 3: return r
		return getLegalEntity(regno, history, count = count + 1)
	return r




def main():
	print('Palaižam datu pieprasījumus')
	start_time = time.time()
	speed = time.time()
	dataRead = 0
	getToken()
	global session
	session = requests.Session()
	if authToken != '':
		csvreader = csv.reader(open('public_data/register.csv', "r", encoding="UTF-8"), delimiter=";")
		for row in csvreader:
			try:
				regno = row[0] #Registrācijas numurs
				regtype = row[7] #Reģistra veids
				terminated = row[12] #izslēgts no reģisra
				if regtype in ('K', 'B', 'U', 'C', 'E') and terminated == '' and os.path.isfile(dataFolder + str(regno) + '.json') == False:
					dataRead += 1
					if dataRead > 200000: break #limits pie kura apturam apstrādi
					if getLegalEntity(regno, True) == False: break
					if dataRead % 100 == 0:
						print("----- %s: speed: %s sec/req, total: %s seconds -----" % (dataRead, (time.time() - speed) / 100, time.time() - start_time))
						speed = time.time()
			except Exception as e:
				print(e)
				print(row)
	else:
		print('Tokens nav izgūts')
	print("--- %s seconds ---" % (time.time() - start_time))

#asyncio.run(main())
if __name__ == "__main__":
    main()