from webapi_client import WebAPIClient
from import_consumer import get_id_and_session_args
from webapi_order_utils import *
import time
import json


# your_consumer_key, user_identifier = "YRAOUCONS", "yraou9449"
your_consumer_key, user_identifier = "TESTCONS", "msull3647"
# your_consumer_key, user_identifier = "RRAPIKEYS", "rrapi982"
# your_consumer_key, user_identifier = "TESTCONS", "msull7236"
# your_consumer_key, user_identifier = "BCONSUMER", "msull3647"
# your_consumer_key, user_identifier = "TESTCONS", "zeroh3352"
# your_consumer_key, user_identifier = "FXLPCNSMR", "msull7236"


def main():
    s = WebAPIClient(
        init_brokerage=True,
        verbose=True,
        proxy=True,
        print_all_headers=False,
        domain="api.ibkr.com",
        env="v1/api",
        **get_id_and_session_args(consumer=your_consumer_key, user=user_identifier),
    )
    # s.request(POST, "/logout")

    # s.get_live_session_token(verbose=True)
    
    acct = s.request(GET, "/portfolio/accounts", verbose=True).json()[0]["id"]

    # s.init_brokerage_session()

    time.sleep(2)

    s.request(GET, "/iserver/accounts", verbose=True)

    s.request(GET, '/trsrv/stocks?symbols=BRK A')

    # # s.request(POST, '/iserver/account', body={'acctId': 'All'})

    # conid = 12087792 # EURUSD
    # fields = ["31", "7059", "84", "86", "85", "88"]

    # s.request(GET, f"/iserver/marketdata/snapshot?conids={conid}&fields={','.join(fields)}")

    # s.request(GET, f"/iserver/marketdata/history?{'&'.join(f'{k}={v}' for k, v in {
    #     'conid': 265598,
    #     'period': '1d', 
    #     'bar': '1hrs', 
    #     'outsideRth': 'true', 
    #     'barType':'Last'
    # }.items())}", verbose=False)

    # s.request(GET, f"/iserver/account/{acct}/summary", verbose=False)

    # # msgids = ["p12", "o0", "o354", "o451", "o10223", "o10164"]
    # # time.sleep(1)
    # # s.request(POST, '/iserver/questions/suppress', body={"messageIds": msgids})

    # # time.sleep(1)

    # s.open_websocket(get_cookie=True, verbose=True)
    # s.send_websocket("sor+{}")
    # s.send_websocket("str+{\"realtimeUpdatesOnly\":false}")
    # s.send_websocket("spl")
    # # s.send_websocket('smd+{}+{"fields":[{}]}'.format(conid, ",".join(f'"{f}"' for f in fields)))

    # time.sleep(1)
    # s.request(GET, f"/iserver/contract/265598/info-and-rules")
    # submit_order(s, acct, [aapl], whatif=False)

    # # time.sleep(2)

    # s.request(GET, '/iserver/account/orders', verbose=True)

    # s.request(GET, '/iserver/account/trades?days=7', verbose=True)

    # i = 0
    # while i < 5:
    #     s.send_websocket("tic+{}")
    #     time.sleep(3)
    #     i = i + 1

    # # time.sleep(15)

    # s.close_websocket()
    # s.request(POST, "/logout")

    


GET, POST, DELETE, PUT = "get", "post", "delete", "put"
BUY, SELL = "BUY", "SELL"

if __name__ == "__main__":
    main()