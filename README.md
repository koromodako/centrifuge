<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">Centrifuge</h2>

<div align="center">

![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
![Powered By: EDF](https://img.shields.io/badge/Powered_By-CERT_EDF-FFFF33.svg?style=for-the-badge)
[![License: MIT](https://img.shields.io/badge/License-MIT-2596be.svg?style=for-the-badge)](/LICENSE)

</div>

# Introduction

Centrifuge is designed to enrich multiple types of data indicators (atoms) using a wide variety of enrichers and can be seamlessly extended by registering new ones at runtime to fit your specific workflow.

**Atom Types**

- URL
- UUID
- CVE IDs
- CWE IDs
- Domain Names
- IP Addresses
- MAC Addresses
- Phone Numbers
- Email Addresses
- USB Vendor and Product IDs
- Digests (MD5, SHA-1, SHA-256, SHA-512)

**Enrichment Sources**

Centrifuge relies on several types of sources to provide deep enrichment data.

- Enrichment data from a **dynamic** source requires requesting data from servers during enrichment
- Enrichment data from a **static** source can be cached prior to enrichment
- An **external** source provides enrichment data for elements outside the organization
- An **internal** source provides enrichment data related to the organization

Lets illustrate these concepts with some examples.

- Onyphe, Censys and VirusTotal are **dynamic external** sources
- Geolocus database `geolocus.mmdb` is a **static external** source
- OpenCTI and Hashlookup are **dynamic internal or external** source depending on your own setup
- Known Identity, Known Network, Known Endpoint, Known Service, Known Entity are **static internal** sources
- Known CVE, Known CWE, Known MAC, Known User-Agent, Known Public Network and more are **static external** sources

You are expected to populate **static internal** sources if you need them.

<br>

## Getting Started

Centrifuge releases are available on [Github](https://github.com/CERT-EDF/centrifuge/releases) and [Pypi](https://pypi.org/project/edf-centrifuge/).

Use Python 3.12+ and a virtual environment for best experience.

```bash
# setup centrifuge using python3 from your virtual environment
python3 -m pip install edf-centrifuge
# setup a postgresql database (if needed) using docker compose
# copy test/compose.yml to compose.yml and customize it to fit your needs
# then start containers using the following command
sudo docker compose up -d
# copy centrifuge.dist.json to centrifuge.json and customize it to fit your needs
# then populate the database before calling enrich for the first time
centrifuge populate
# enrich the atom of your choice
centrifuge enrich 'https://github.com/cert-edf/centrifuge' | jq
```

<br>

## Configuration

You can find a template in [centrifuge.dist.json](https://github.com/CERT-EDF/centrifuge/blob/main/centrifuge.dist.json).

<br>

## License

Distributed under the MIT License.

<br>

## Contributing

Contributions are welcome, see [CONTRIBUTING.md](https://github.com/CERT-EDF/centrifuge/blob/main/CONTRIBUTING.md) for more information.

<br>

## Security

To report a (suspected) security issue, see [SECURITY.md](https://github.com/CERT-EDF/centrifuge/blob/main/SECURITY.md) for more information.
