# Public capture provenance

Downloaded from the official Stratosphere/CTU-13 repository for offline research.
No malware binaries were downloaded or executed.

Source: https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/

Attribution: Garcia, Sebastian. Malware Capture Facility Project.
https://stratosphereips.org. Dataset reference: Sebastian Garcia, Martin Grill,
Jan Stiborek and Alejandro Zunino, “An empirical comparison of botnet detection
methods”, Computers & Security 45 (2014), 100–123,
https://doi.org/10.1016/j.cose.2014.05.011.
The source README permits use with attribution to the project and authors.

| File | Bytes | SHA-256 |
|---|---:|---|
| botnet-capture-20110816-sogou.pcap | 18,868,213 | ff5c18adaa6a4681df1db43d0eac10d05e65d51931d5380ca54ceff0d005d2c5 |
| capture20110816-2.binetflow | 15,630,512 | df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680 |

Files are under `data/external/ctu13-7/`, excluded from git. Reproduce:

```bash
mkdir -p data/external/ctu13-7
curl -fL --retry 2 -o data/external/ctu13-7/botnet-capture-20110816-sogou.pcap https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/botnet-capture-20110816-sogou.pcap
curl -fL --retry 2 -o data/external/ctu13-7/capture20110816-2.binetflow https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/capture20110816-2.binetflow
IGU_FEATURE_CONTRACT_VERSION=2 .venv/bin/python scripts/extract-public-capture.py --pcap data/external/ctu13-7/botnet-capture-20110816-sogou.pcap --labels data/external/ctu13-7/capture20110816-2.binetflow --output data/external/ctu13-7/extracted
```

The extraction produced **3,366 records**, with no reported packet-window drops
or late packets, in about **19 seconds** on this machine. This measures extraction,
not detector accuracy or sustained live capture throughput.

The label file includes normal, background and botnet flows over the wider
network. The released PCAP is the infected-host capture. Records must be joined
by validated endpoint tuples and timestamp intervals; background is not benign,
a download is not exfiltration, and a botnet label does not prove beaconing or
encrypted malware. This acquisition is not enough to validate all six PS classes.

CIC-Bell-DNS-EXF-2021's official download page requested personal details; no
identity was fabricated or form submitted. Additional representative datasets
remain an evaluation requirement, not a blocker to the completed tooling.
