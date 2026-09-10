"""Connection URLs must open the console; failed releases must never be downloads."""
from unittest.mock import MagicMock, patch
import socket
from fastapi.testclient import TestClient
from app import server


def test_download_redirects_use_available_distribution_paths():
    client = TestClient(server.app)
    for route, filename in [('apk','SafeerCompanion.apk'),('tv-binary','safeer-companion-android-arm64'),('linux-binary','safeer-companion-linux-amd64')]:
        response=client.get('/download/'+route,follow_redirects=False)
        assert response.status_code==302
        assert response.headers['location']=='https://safeer.si/downloads/'+filename


def test_mdns_url_matches_advertised_name_and_console():
    with patch('zeroconf.Zeroconf') as zc, patch('zeroconf.ServiceInfo') as info, patch('socket.gethostname',return_value='test-pc'), patch('atexit.register'):
        url=server._start_mdns(8990,'192.0.2.10')
        assert url=='http://test-pc.local:8990/console'
        assert info.call_args.kwargs['server']=='test-pc.local.'
        assert info.call_args.kwargs['properties'][b'path']==b'/console'
        zc.return_value.register_service.assert_called_once()


def test_mdns_failure_falls_back_without_fake_hostname():
    with patch('zeroconf.Zeroconf',side_effect=OSError('unavailable')):
        assert server._start_mdns(8990,'192.0.2.10') is None


def test_startup_qr_and_ip_alternative_open_console(capsys):
    with patch.object(server,'_get_lan_ips',return_value=['192.0.2.10']), patch.object(server,'_start_mdns',return_value=None), patch.object(server,'_print_qr') as qr, patch('uvicorn.run'), patch('socket.socket'):
        server.start_server(port=8990)
    qr.assert_called_once_with('http://192.0.2.10:8990/console')
    assert 'http://192.0.2.10:8990/console' in capsys.readouterr().out
