import asyncio,json
import mcp_server

TOOLS={'hunter_stealth_request','hunter_stealth_scan','hunter_session_create','hunter_session_state','hunter_set_proxy_pool'}

def test_stealth_tools_registered_and_contracted():
    registered={name for name,value in vars(mcp_server).items() if name.startswith('hunter_') and callable(value)}
    assert TOOLS <= registered
    contract=json.loads(asyncio.run(mcp_server.hunter_contract_check()))
    assert TOOLS <= set(contract['data']['required_tools'])


def test_stealth_mcp_session_and_proxy_smoke(tmp_path):
    mcp_server._reset_stealth_client(tmp_path)
    created=json.loads(asyncio.run(mcp_server.hunter_session_create('https://fixture',resume=False)))
    assert created['status']=='ok'
    state=json.loads(asyncio.run(mcp_server.hunter_session_state('https://fixture')))
    assert state['data']['fingerprint_id']==created['data']['fingerprint_id']
    proxies=json.loads(asyncio.run(mcp_server.hunter_set_proxy_pool(['http://127.0.0.1:8080'])))
    assert proxies['data']['total']==1
