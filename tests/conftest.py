"""Fixtures comunes.

Lo importante aqui es MEDSCAN_DATA: sin el, las pruebas escribirian en la base
de datos real del usuario. config.data_dir() lee la variable en cada llamada,
asi que basta con apuntarla a un directorio temporal antes de tocar nada.
"""

from __future__ import annotations

import pytest

from medscan import db

# Salida realista de nmap: dos hosts, servicios con version, un script NSE que
# confirma MS17-010 y otro que declara NOT VULNERABLE.
NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sS -p- -sV 192.168.1.10" start="1758200000" version="7.95">
<scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>
<host starttime="1758200001" endtime="1758200120">
<status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="00:0C:29:3A:1B:2C" addrtype="mac" vendor="VMware"/>
<hostnames><hostname name="servidor.local" type="PTR"/></hostnames>
<ports>
<extraports state="closed" count="65530"><extrareasons reason="resets" count="65530"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="6.6.1p1" extrainfo="Ubuntu" method="probe" conf="10">
<cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe></service>
</port>
<port protocol="tcp" portid="23"><state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="telnet" product="Linux telnetd" method="probe" conf="10"/>
</port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="microsoft-ds" product="Samba smbd" version="3.0.20" method="probe" conf="10"/>
<script id="smb-vuln-ms17-010" output="&#10;  VULNERABLE:&#10;  Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)&#10;    State: VULNERABLE&#10;    IDs:  CVE:CVE-2017-0143&#10;    Risk factor: HIGH&#10;"/>
</port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="https" product="nginx" version="1.24.0" tunnel="ssl" method="probe" conf="10"/>
<script id="ssl-heartbleed" output="&#10;  NOT VULNERABLE:&#10;    State: NOT VULNERABLE&#10;"/>
<script id="ssl-cert" output="Subject: commonName=servidor.local"/>
</port>
<port protocol="tcp" portid="1234"><state state="closed" reason="reset" reason_ttl="64"/>
<service name="hotline" method="table" conf="3"/>
</port>
</ports>
<os><osmatch name="Linux 3.2 - 4.9" accuracy="95"/><osmatch name="Linux 2.6" accuracy="88"/></os>
</host>
<host starttime="1758200001" endtime="1758200120">
<status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.11" addrtype="ipv4"/>
</host>
<runstats><finished time="1758200121" elapsed="121.45" summary="Nmap done" exit="success"/>
<hosts up="1" down="1" total="2"/></runstats>
</nmaprun>
"""


@pytest.fixture(autouse=True)
def datos_temporales(tmp_path, monkeypatch):
    """Aisla cada prueba en su propio directorio de datos."""
    monkeypatch.setenv("MEDSCAN_DATA", str(tmp_path / "datos"))
    db.init_db()
    return tmp_path


@pytest.fixture
def nmap_xml() -> str:
    return NMAP_XML


@pytest.fixture
def xml_file(tmp_path, nmap_xml):
    path = tmp_path / "scan.xml"
    path.write_text(nmap_xml, encoding="utf-8")
    return path
