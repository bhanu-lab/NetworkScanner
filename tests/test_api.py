from network_scanner import Device, Interface, MetadataStore, ScanError
from main import create_app


class FakeScanner:
    store=MetadataStore()
    def interfaces(self): return [Interface('eth0','192.168.1.2','255.255.255.0','192.168.1.0/24',True)]
    def scan(self,name,details=False):
        if name!='eth0': raise ScanError('bad interface')
        device=Device('192.168.1.2',is_local=True,device_type='this device')
        if details: device.operating_system='Linux'
        return [device.to_dict()],.12


def client(): return create_app(FakeScanner()).test_client()


def test_health_and_interfaces():
    assert client().get('/api/health').json == {'persistence':False,'status':'ok'}
    assert client().get('/api/interfaces').json[0]['network'] == '192.168.1.0/24'
    assert client().get('/api/interfaces').json[0]['id'] == 'eth0@192.168.1.2'


def test_scan_contract_and_validation():
    response=client().post('/api/scans',json={'interface':'eth0'})
    assert response.status_code==200 and response.json['count']==1
    assert response.json['details'] is False
    response=client().post('/api/scans',json={'interface':'eth0','details':True})
    assert response.json['devices'][0]['operating_system']=='Linux'
    assert client().post('/api/scans',json={}).status_code==400
    assert client().post('/api/scans',json=[]).status_code==400
    assert client().post('/api/scans',json={'interface':'eth0','details':'yes'}).status_code==400
