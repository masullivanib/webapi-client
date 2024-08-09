from typing import Callable
import json
import requests
import random
import base64
import websocket
import threading
from pathlib import Path
from datetime import datetime
from time import time, ctime
from urllib.parse import quote, quote_plus, unquote
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1


#TODO: Smart brokerage session readiness using websocket

class WsTopicHandler:
    def __init__(
            self, 
            topic: str,
            verbose: bool = True, 
            method: Callable = None, 
            custom_log_path: str = None,
        ):
        self.topic = topic
        self.verbose = verbose
        self.on_msg_method = method
        self.custom_log_path = custom_log_path
    
    def on_msg(self, jmsg: str):
        return self.on_msg_method(jmsg)
    

class WebAPIClient:
    """Class to handle web API session with authentication via OAuth."""

    def __init__(
        self,
        *,
        init_brokerage: bool = True,
        verbose: bool = True,
        print_all_headers: bool = False,
        logging: bool = True,
        log_path: str = "",
        proxy: bool = False,
        domain: str = 'api.ibkr.com',
        env: str = 'v1/api',
        consumer_key: str,
        encryption_key: bytes,
        signature_key: bytes,
        dhparam: bytes,
        access_token: str,
        access_token_secret: str,
        live_session_token: str = "",
        lst_expiration: int = 0,
        session_cookie: str = "",
        session_cookie_updated: int = 0,
        session_cache_path: str
    ):
        self.execution_start_time = int(time()*1000)
        self.first_request_flag = True
        
        self.session_object = requests.Session()
        self.user_agent = "python/3.11"
        self.websocket = None
        self.ws_thread = None
        self.ws_open_flag = threading.Event()
        self.ws_topics = {}

        self.proxy = proxy
        self.domain, self.env = domain, env
        self.logging, self.verbose = logging, verbose
        self.headers_to_print = lambda rhs: rhs & {
            "Content-Type", 
            "Content-Length", 
            "Date", 
            "Set-Cookie"
        } if not print_all_headers else rhs

        self.consumer_key = consumer_key
        self.realm = "test_realm" if consumer_key == "TESTCONS" else "limited_poa"
        self.access_token = access_token
        self.access_token_secret = access_token_secret

        self.simple_auth = True if access_token_secret == None else False

        try:
            self.session_cache_path = Path(session_cache_path).resolve(strict=False)
            self.session_cache_path.touch(exist_ok=True)
            if self.logging:
                self.log_path = Path(log_path).expanduser().resolve(strict=False)
                self.log_path.touch(exist_ok=True)
        except (OSError, ValueError) as e:
            print(f"***E: {e}\nExiting...")
            raise SystemExit(0)
        
        self.session_cookie = session_cookie
        self.session_cookie_updated = session_cookie_updated

        if self.simple_auth:
            self.live_session_token = ""
            self.lst_expiration = 0
        else:
            try:
                self.encryption_key = RSA.importKey(encryption_key)
                self.signature_key = RSA.importKey(signature_key)
                self.dhparam = RSA.importKey(dhparam)
            except (ValueError, IndexError) as e:
                print(f"***E: {e}\n{{}}\nExiting...".format(
                    "Ensure that the provided key data bytestrings are valid, PEM-encoded RSA keys."
                ))
                raise SystemExit(0)
            
            if not live_session_token or self.__is_lst_expiring(lst_expiration):
                self.get_live_session_token()
            else:
                self.live_session_token = live_session_token
                self.lst_expiration = lst_expiration
                print("***I: Valid LST found: {} expires {}\n".format(
                    self.live_session_token,
                    ctime(self.lst_expiration/1000)
                ))

        if init_brokerage:
            self.init_brokerage_session(verbose=False)

    def __is_lst_expiring(self, lst_expiration: int) -> bool:
        """Tests whether the current time is within 10 minutes of the stored
        LST expiration time. (10 mins = 600000 milliseconds)

        Parameters:
            lst_expiration (int): Unix epoch timestamp of LST's expiration 
            in milliseconds
        Returns:
            bool: True if LST is 10 minutes from expiration, False otherwise
        """
        if lst_expiration - int(time()*1000) < 600000:
            return True
        else:
            return False

    def __make_auth_header(
            self,
            method: str,
            url: str,
            query_params: dict = None,
            dh_challenge: str = None,
            prepend: str = None,
        ) -> dict:
        """Builds the Authorization header string for any request, before or
        after obtaining a LST.

        Parameters:
            method (str): request's HTTP method
            url (str): request's base URL without query params
            query_params (dict): key-value pairs of request's query params
            dh_challenge (str): LST request's Diffie-Hellman challenge value
            prepend (str): LST request's signature prepend value
        Returns:
            dict: Single key pair, {"Authorization": "OAuth PARAMS_STRING"}
        """

        if self.simple_auth:
            return {"Authorization": f"OAuth oauth_token=\"{self.access_token}\""}

        base_string = ""
        oauth_params = { # auth param defaults
            "oauth_consumer_key": self.consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": self.access_token
        }

        if prepend is not None:  # Check if LST request
            oauth_params["oauth_signature_method"] = "RSA-SHA256"
            oauth_params["diffie_hellman_challenge"] = dh_challenge
            base_string += prepend

        params_dict = oauth_params if query_params is None else {**oauth_params, **query_params}
        params_string = "&".join([f"{k}={v}" for k, v in sorted(params_dict.items())])
        base_string += f"{method}&{quote_plus(url)}&{quote(params_string)}"
        encoded_base_string = base_string.encode("utf-8")

        if prepend is not None: # Check if LST request
            sha256_hash = SHA256.new(data=encoded_base_string)
            bytes_pkcs115_signature = PKCS1_v1_5_Signature.new(
                rsa_key=self.signature_key
                ).sign(msg_hash=sha256_hash)
            b64_str_pkcs115_signature = base64.b64encode(bytes_pkcs115_signature).decode("utf-8")
            oauth_params['oauth_signature'] = quote_plus(b64_str_pkcs115_signature)
        else:
            bytes_hmac_hash = HMAC.new(
                key=base64.b64decode(self.live_session_token), 
                msg=encoded_base_string,
                digestmod=SHA256
                ).digest()
            b64_str_hmac_hash = base64.b64encode(bytes_hmac_hash).decode("utf-8")
            oauth_params["oauth_signature"] = quote_plus(b64_str_hmac_hash)
        oauth_params["realm"] = self.realm
        oauth_header = "OAuth " + ", ".join(
            [f'{k}="{v}"' for k, v in sorted(oauth_params.items())]
        )
        return {"Authorization": oauth_header}
    
    def get_live_session_token(self, verbose=True) -> None:
        """Constructs and sends request to /live_session_token endpoint.
        If request is successful, computes LST from the returned DH response, 
        validates computed LST against the returned LST signature, and caches
        the newly-created LST and expiration for use with future requests.

        Parameters:
            verbose (bool): Controls print output to stdout, passed through
            to __send_request() method
        Returns:
            None
        """
        method = "POST"
        url = f"https://{self.domain}/{self.env}/oauth/live_session_token"

        dh_random = random.getrandbits(256)
        dh_challenge = hex(pow(base=self.dhparam.e, exp=dh_random, mod=self.dhparam.n))[2:]
        bytes_decrypted_secret = PKCS1_v1_5_Cipher.new(
            key=self.encryption_key
            ).decrypt(
                ciphertext=base64.b64decode(self.access_token_secret), 
                sentinel=None,
                )
        prepend = bytes_decrypted_secret.hex()
        auth_header = self.__make_auth_header(method, url, None, dh_challenge, prepend)

        # Send request to /live_session_token
        lst_response = self.__send_request(
            verbose=verbose, 
            method=method,
            url=url,
            headers=auth_header,
            )
        if not lst_response.ok:
            print(f"***E: Request to /live_session_token failed. Exiting...")
            raise SystemExit(0)
        else:
            response_data = lst_response.json()
            dh_response = response_data["diffie_hellman_response"]
            lst_signature = response_data["live_session_token_signature"]
            lst_expiration = response_data["live_session_token_expiration"]
            
            # Compute LST
            prepend_bytes = bytes.fromhex(prepend)
            a = dh_random
            B = int(dh_response, 16)
            p = self.dhparam.n
            K = pow(B, a, p)
            hex_str_K = hex(K)[2:]
            if len(hex_str_K) % 2: # Add leading 0 if odd num chars because python requires 2-char hex digits
                print("***D: Adding leading 0 for even number of chars")
                hex_str_K = "0" + hex_str_K
            hex_bytes_K = bytes.fromhex(hex_str_K)

            if len(bin(K)[2:]) % 8 == 0:
                hex_bytes_K = bytes(1) + hex_bytes_K # Prepend null byte if lacking sign bit
            bytes_hmac_hash_K = HMAC.new(
                key=hex_bytes_K,
                msg=prepend_bytes,
                digestmod=SHA1,
                ).digest()
            computed_lst = base64.b64encode(bytes_hmac_hash_K).decode("utf-8")

            # Validate LST
            hex_str_hmac_hash_lst = HMAC.new(
                key=base64.b64decode(computed_lst),
                msg=self.consumer_key.encode("utf-8"),
                digestmod=SHA1,
            ).hexdigest()
            if hex_str_hmac_hash_lst == lst_signature:
                self.live_session_token = computed_lst
                self.lst_expiration = lst_expiration
                self.__write_session_cache()
                print(f"***I: Generated new LST: {computed_lst} expires {ctime(lst_expiration/1000)}\n")
            else:
                print(f"***E: LST validation failed. Exiting...")
                raise SystemExit(0)

    def __write_session_cache(self) -> None:
        self.session_cache_path.write_text(json.dumps({
                'live_session_token': self.live_session_token,
                'lst_expiration': self.lst_expiration,
                'session_cookie': self.session_cookie,
                'session_cookie_updated': self.session_cookie_updated,
            }
        ))

    def __send_request(
            self, 
            verbose: bool,
            custom_log_path: str = None, 
            **kwargs,
        ) -> requests.Response:
        """Helper method to dispatch, print, and log arbitrary HTTP requests.
        
        Parameters:
            verbose (bool): True prints complete request and response, 
                False prints only request URL and response status
            **kwargs (Any): Elements of the request
        Returns:
            requests.Response object
        """
        verbose = self.verbose if verbose is None else verbose
        req = requests.Request(**kwargs).prepare()
        self.__print_and_log_request(req=req, verbose=verbose, logging=self.logging, custom_log_path=custom_log_path)
        if self.proxy:
            resp = self.session_object.send(req, allow_redirects=False, proxies={"https": "127.0.0.1:8080"}, verify=False)
        else:
            resp = self.session_object.send(req, allow_redirects=False)
        self.__print_and_log_response(resp=resp, verbose=verbose, logging=self.logging, custom_log_path=custom_log_path)
        if 'api' in resp.cookies.get_dict():
            self.session_cookie = resp.cookies.get_dict()['api']
            self.session_cookie_updated = int(time()*1000)
            self.__write_session_cache()
        return resp

    def request(
            self,
            method: str,
            path: str,
            body: dict = None,
            headers: dict = {},
            domain: str = None,
            env: str = None,
            verbose: bool = None,
            custom_log_path: str = None,
        ) -> requests.Response:
        """Method for making all post-LST requests. Assembles all elements of
        request. First calls __is_lst_expiring() to test age of cached LST and
        obtain new LST if nearing expiration. Then contructs headers dict with
        call to __make_auth_header() for OAuth Authorization header. Adds 
        Cookie header if cached session value exists. Calls __send_request()
        to dispatch and receives requests.Response object back.
        
        Parameters:
            method (str): Request's HTTP method
            path (str): Request's URI path
            body (dict): Request's JSON payload
            headers (dict): Manually supplied headers for request
            domain (str): IB domain for request
            env (str): Web API environment (v1 or alpha)
            verbose (bool): Controls print output to stdout, passed through
            to __send_request() method
        Returns:
            dict | str: Response's JSON body dict returned if it exists,
            otherwise Response.text, which also covers failed requests
        """
        domain = self.domain if domain is None else domain
        env = self.env if env is None else env

        if not self.simple_auth and self.__is_lst_expiring(self.lst_expiration):
            self.get_live_session_token()
        req_headers = {'User-Agent': 'python/3.11'}
        if self.session_cookie:
            req_headers['Cookie'] = f"api={self.session_cookie}"

        method = method.upper()
        query_params_dict = {}
        if '?' in path:
            base_uri, query_params_str = path.split('?')
            query_params_list = query_params_str.split('&')
            for qp in query_params_list:
                if '=' in qp:
                    k, v = qp.split('=')
                    query_params_dict[k] = v
        else:
            base_uri = path

        url = f"https://{domain}/{env}{base_uri}"

        auth_header = self.__make_auth_header(method, url, query_params_dict)
        req_headers.update(auth_header) # add Authorization header to dict of request's headers
        req_headers.update(headers) # let manually supplied headers overwrite defaults

        response = self.__send_request(
            verbose=verbose,
            custom_log_path=custom_log_path,
            method=method,
            url=url,
            headers=req_headers,
            params=query_params_dict,
            json=body,
            )
        if response.status_code == 401 and self.first_request_flag and not self.simple_auth:
            self.get_live_session_token(verbose)
            self.first_request_flag = False
            response = self.request(method, path, body, headers, domain, env, verbose)
        return response

    def init_brokerage_session(
            self, 
            compete: bool = True, 
            publish: bool = True,
            renew: bool = False,
            verbose: bool = False,
        ) -> dict | str:
        """Method specifically for making request to /iserver/auth/ssodh/init
        for opening brokerage session. This method is for convenience, and
        this request is no different from any other post-LST request. Calls
        request() method.
        
        Parameters:
            compete (bool): Request query param, must be True
            publish (bool): Request query param, must be True
            renew (bool): Forces this method to open a new brokerage session
            without first testing if one exists
            verbose (bool): Controls print output to stdout, passed through
            to __send_request() method
        Returns:
            dict | str: Passes through request() method's return value, either
            Response's JSON body dict or Response.text
        """
        if renew:
            auth_status = False
            print_mask = '***I: Force-renew brokerage session: authenticated={}\n'
        else:
            response = self.request(
                "POST", 
                "/iserver/auth/status", 
                verbose=verbose,
                )
            auth_status = response.json()["authenticated"]

        if auth_status:
            print_mask = '***I: Brokerage session already exists: authenticated={}\n'
        else:
            params = f"publish={publish}&compete={compete}".lower()
            response = self.request(
                "GET", 
                f"/iserver/auth/ssodh/init?{params}", 
                verbose=verbose,
                )
            try:
                auth_status = response.json()["authenticated"]
                if bool(auth_status):
                    print_mask = '***I: Opened brokerage session: authenticated={}\n'
                else:
                    print_mask = '***E: Failed to open brokerage session: authenticated={}\n'
            except requests.JSONDecodeError as e:
                auth_status = f"{response.status_code} {response.reason} {response.text}"
                print_mask = '***E: Request to /iserver/auth/ssodh/init failed: {}\n'

        print(print_mask.format(auth_status))
        return response
    
    def logout(self, verbose: bool = False):
        self.session_cookie = ""
        self.session_cookie_updated = 0
        self.__write_session_cache()
        response = self.request("POST", "/logout", verbose=verbose)
        return response
    
    def open_websocket(
            self,
            get_cookie: bool = True,
            verbose: bool = False,
            ) -> dict | str:
        if get_cookie:
            self.get_session_cookie(verbose)
        self.ws_thread = threading.Thread(target=self.__run_websocket, args=[verbose], daemon=False)
        self.ws_thread.start()

    def send_websocket(
            self, 
            message: str = "",
            json: dict = {},
            verbose: bool = True,
            force: bool = False,
            method = None,
            custom_log_path: str = None,
        ) -> bool:
        def __thread_send(message: str, verbose: bool):
            self.ws_open_flag.wait()
            self.__print_and_log_ws_message(
                recv=False, 
                msg=message, 
                verbose=verbose, 
                logging=self.logging,
                custom_log_path=custom_log_path,
            )
            self.websocket.send(message)
            
        if self.ws_thread.is_alive():
            if '{"session":' in message or force:
                self.__print_and_log_ws_message(
                    recv=False, 
                    msg=message, 
                    verbose=True, 
                    logging=self.logging,
                    custom_log_path=None,)
                self.websocket.send(message)
            else:
                if message[-1] == '+':
                    message = f"{message}{self.jsonner(json, 0, True)}"
                elif message[-1] == '}':
                    message = message.replace("'", '"').replace(' ', '')
                else:
                    message = f"{message}+{self.jsonner(json, 0, True)}"
                topic = message.split('+{')[0]
                self.add_ws_topic(topic, verbose, method, custom_log_path)
                threading.Thread(target=__thread_send, args=[message, verbose], daemon=False).start()
            return True
        else:
            print("***E: Websocket does not exist.")
            return False
        
    def close_websocket(self) -> bool:
        if not self.websocket:
            print("***W: Ignored close_websocket.")
            return False
        self.websocket.close(status=1000)
        return True

    def __run_websocket(self, verbose: bool = False,) -> dict | str:
        ws_url = f"wss://{self.domain}/{self.env}/ws?oauth_token={self.access_token}"
        cookie_arg = {"cookie": f"api={self.session_cookie}"} if self.session_cookie else {}
        user_agent = {"User-Agent": self.user_agent}
        self.__print_and_log_request(
            req=(ws_url, dict(**cookie_arg, **user_agent)), 
            verbose=verbose, 
            logging=self.logging,
        )
        self.websocket = websocket.WebSocketApp(
            url=ws_url,
            on_error=self.__ws_on_error,
            on_close=self.__ws_on_close,
            on_message=self.__ws_on_message, 
            header=[f"{k}: {v}" for k, v in user_agent.items()],
            **cookie_arg,
            )
        self.__print_and_log_response(
            resp=self.websocket.has_errored, 
            verbose=verbose, 
            logging=self.logging,
        )
        self.websocket.on_open = self.__ws_on_open
        self.websocket.run_forever()
    
    def __ws_on_open(self, websocket):
        print("***I: Websocket open.")

    def __ws_on_error(self, websocket, error):
        pass

    def __ws_on_close(self, websocket, close_status_code, close_msg):
        self.ws_open_flag.clear()
        self.websocket = None
        print("***I: Websocket closed.")

    def __ws_on_message(self, websocket, message):
        str_msg = message.decode('utf-8')
        if '"sts"' in str_msg: # previously used 'system' msg as ws-ready signal, but this is too early
            self.ws_open_flag.set()
        try:
            json_msg = json.loads(str_msg)
            if 'topic' in json_msg:
                tpc = json_msg['topic']
                if tpc in self.ws_topics:
                    self.__print_and_log_ws_message(
                        recv=True, 
                        msg=str_msg, 
                        verbose=self.ws_topics[tpc].verbose, 
                        logging=self.logging, 
                        custom_log_path=self.ws_topics[tpc].custom_log_path,
                    )
                    self.ws_topics[tpc].on_msg(json_msg)
                else:
                    self.__print_and_log_ws_message(
                        recv=True, 
                        msg=str_msg, 
                        verbose=True, 
                        logging=self.logging,
                        custom_log_path=None,
                    )
            if json_msg['message'] == 'waiting for session':
                if not self.session_cookie:
                    self.get_session_cookie()
                self.send_websocket(message=f"{{\"session\":\"{self.session_cookie}\"}}")
        except json.JSONDecodeError:
            print(f"***E: Decode error: {message}")
        
            
    def get_session_cookie(self, verbose: bool = False) -> str:
        self.session_cookie = self.request("POST", "/tickle", verbose=verbose).json()["session"]
        self.session_cookie_updated = int(time()*1000)
        print('***I: Got session cookie: {} retrieved {}'.format(
            self.session_cookie,
            ctime(self.session_cookie_updated/1000),
        ))
        self.__write_session_cache()
        return self.session_cookie
    
    def jsonner (self, obj, depth: int, flat: bool = False) -> str:
        if isinstance(obj, str): return f"\"{obj}\""
        if isinstance(obj, (int, float, bool)): return str(obj).lower()
        if obj is None: return 'null'
        outstr, idt, max_w, n_items, is_dict = '', 2, 70, len(obj), isinstance(obj, dict)
        if flat:
            for i in range(0, n_items):
                k, v = (lambda x, y: (f"\"{x}\":", y))(*list(obj.items())[i]) if is_dict else ('', obj[i])
                outstr += f"{k}{self.jsonner(v, depth + 1, flat)}{','*(i != n_items - 1)}"
            outstr = f"{'[{'[is_dict]}{outstr}{']}'[is_dict]}"
            return outstr
        else:
            for i in range(0, n_items):
                k, v = (lambda x, y: (f"\"{x}\": ", y))(*list(obj.items())[i]) if is_dict else ('', obj[i])
                outstr += f"{(depth + 1)*idt*' '}{k}{self.jsonner(v, depth + 1, flat)}{',\n'*(i != n_items - 1)}"
            outstr = f"{'[{'[is_dict]}\n{outstr}\n{depth*idt*' '}{']}'[is_dict]}"
            return " ".join(s.strip() for s in outstr.split("\n")) if len(outstr) < max_w else outstr
    
    def __print_and_log_request(
            self, 
            req: requests.PreparedRequest | tuple, 
            verbose: bool, 
            logging: bool,
            custom_log_path: str = '',
    ) -> None:
        tstamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if isinstance(req, tuple):
            rqm, rqu, rqh, rqb = 'GET', req[0], req[1], ''
        else:
            rqm, rqu, rqh = req.method, req.url, req.headers
            rqb = f"\n{self.jsonner(json.loads(req.body), 0)}\n" if req.body else ""
        rqh_fmt = '\n'.join(f"{k}: {v}" for k, v in rqh.items()).replace(', ', ',\n    ')
        short_str = f"{tstamp} REQUEST{58*'-'}\n{rqm} {unquote(rqu)}"
        long_str = f"{short_str}\n{rqh_fmt}\n{rqb}"
        if logging:
            with self.log_path.open('a') as f:
                f.write(long_str)
        if custom_log_path:
            with custom_log_path.open('a') as f:
                f.write(long_str)
        print(long_str) if verbose else print(short_str)
            
    def __print_and_log_response(
            self, 
            resp: requests.Response | bool, 
            verbose: bool, 
            logging: bool,
            custom_log_path: str = '',
    ) -> None:
        tstamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if isinstance(resp, bool):
            rsc, rsr = 'Has errored:', str(resp)
            rtt = rsh = rsb = ''
        else:
            rsc, rsr = resp.status_code, resp.reason
            rsh_to_show = self.headers_to_print(set(resp.headers.keys()))
            rsh = '\n'.join([f"{k}: {v}" for k, v in resp.headers.items() if k in rsh_to_show])
            rtt = f"elapsed={round(resp.elapsed.total_seconds()*1000, 3)}\n"
            try:
                rsb = f"\n{self.jsonner(resp.json(), 0)}\n" if resp.text else ""
            except json.JSONDecodeError:
                rsb = resp.text
        short_str = f"{rsc} {rsr}\n"
        long_str = f"{tstamp} RESPONSE {rtt}{short_str}{rsh}\n{rsb}\n"
        if logging:
            with self.log_path.open('a') as f:
                f.write(long_str)
        if custom_log_path:
            with custom_log_path.open('a') as f:
                f.write(long_str)
        print(long_str) if verbose else print(short_str)
        
    def __print_and_log_ws_message(
            self, 
            recv: bool,
            msg: str,
            verbose: bool,
            logging: bool,
            custom_log_path: str = '',
    ) -> None:
        tstamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if recv:
            recv_str = f"{tstamp} -> WS RECV"
            try:
                json_msg = json.loads(msg)
                short_str = f"{recv_str} {json_msg['topic']}\n"
                long_str = f"{recv_str} {json_msg['topic']} {self.jsonner(json_msg, 0)}\n"
            except:
                short_str = long_str = f"{recv_str} {msg}\n"
        else:
            short_str = long_str = f"\n{tstamp} <- WS SEND {msg}\n"
        if logging:
            with self.log_path.open('a') as f:
                f.write(long_str)
        if custom_log_path:
            with custom_log_path.open('a') as f:
                f.write(long_str)
        print(long_str) if verbose else print(short_str)


    def add_ws_topic(
            self, 
            topic: str, 
            verbose: bool = True, 
            method: Callable = None, 
            custom_log_path: str = None,
    ) -> None:
        self.ws_topics[topic] = WsTopicHandler(topic, verbose, method, custom_log_path)

    def rem_ws_topic(
            self,
            topic: str,
    ) -> None:
        del self.ws_topics[topic]