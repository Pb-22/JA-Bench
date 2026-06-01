import shutil
from pathlib import Path
from subprocess import CompletedProcess

from scapy.all import Ether, IP, TCP
from scapy.utils import PcapNgWriter

from app import pcap_reader_service
from app.pcap_reader_service import _iter_capture_packets


def _write_sample_pcapng(path: Path) -> None:
    writer = PcapNgWriter(str(path))
    writer.write(Ether() / IP(src="10.0.0.1", dst="1.1.1.1") / TCP(sport=12345, dport=443))
    writer.close()


def test_iter_capture_packets_reads_pcapng(tmp_path: Path):
    pcapng_path = tmp_path / "sample.pcapng"
    _write_sample_pcapng(pcapng_path)

    packets = list(_iter_capture_packets(pcapng_path))

    assert len(packets) == 1
    assert packets[0][IP].src == "10.0.0.1"
    assert packets[0][IP].dst == "1.1.1.1"


def test_iter_capture_packets_converts_with_editcap_when_direct_read_fails(tmp_path: Path, monkeypatch):
    pcapng_path = tmp_path / "sample.pcapng"
    _write_sample_pcapng(pcapng_path)
    original_reader = pcap_reader_service.PcapReader
    calls = []

    def flaky_reader(path: str):
        calls.append(Path(path).suffix)
        if len(calls) == 1:
            raise ValueError("direct reader could not open capture")
        return original_reader(path)

    def fake_run(cmd, **kwargs):
        shutil.copyfile(cmd[-2], cmd[-1])
        return CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(pcap_reader_service, "PcapReader", flaky_reader)
    monkeypatch.setattr(pcap_reader_service.subprocess, "run", fake_run)

    packets = list(_iter_capture_packets(pcapng_path))

    assert len(packets) == 1
    assert calls == [".pcapng", ".pcap"]
    assert packets[0][IP].dst == "1.1.1.1"
