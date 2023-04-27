polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  vulnerabilities: Ember.computed('details.vulnerabilities', function () {
    return this.get('details.vulnerabilities');
  }),
  asset: Ember.computed('details.asset', function () {
    return this.get('details.asset');
  })
});

const data = {
  entity: {
    type: 'domain',
    types: ['domain'],
    isIP: false,
    isIPv4: false,
    isIPv6: false,
    isPrivateIP: false,
    IPType: '',
    isHex: false,
    isHash: false,
    isMD5: false,
    isSHA1: false,
    isSHA256: false,
    isSHA512: false,
    hashType: '',
    isGeo: false,
    isEmail: false,
    isURL: false,
    isDomain: true,
    isHTMLTag: false,
    latitude: 0,
    longitude: 0,
    channels: [],
    rawValue: 'ec2-18-222-120-164.us-east-2.compute.amazonaws.com',
    requestContext: {
      isUserInitiated: true,
      requestType: 'OnDemand'
    },
    value: 'ec2-18-222-120-164.us-east-2.compute.amazonaws.com'
  },
  data: {
    summary: [],
    details: {
      vulnerabilities: [
        {
          count: 1,
          plugin_family: 'Web Servers',
          plugin_id: 10107,
          plugin_name: 'HTTP Server Type and Version',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 10287,
          plugin_name: 'Traceroute Information',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Web Servers',
          plugin_id: 10302,
          plugin_name: 'Web Server robots.txt Information Disclosure',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Web Servers',
          plugin_id: 10386,
          plugin_name: 'Web Server No 404 Error Code Check',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 10863,
          plugin_name: 'SSL Certificate Information',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Port scanners',
          plugin_id: 11219,
          plugin_name: 'Nessus SYN scanner',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 11936,
          plugin_name: 'OS Identification',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 12053,
          plugin_name: 'Host Fully Qualified Domain Name (FQDN) Resolution',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Settings',
          plugin_id: 19506,
          plugin_name: 'Nessus Scan Information',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 21643,
          plugin_name: 'SSL Cipher Suites Supported',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Service detection',
          plugin_id: 22964,
          plugin_name: 'Service Detection',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Web Servers',
          plugin_id: 24260,
          plugin_name: 'HyperText Transfer Protocol (HTTP) Information',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 25220,
          plugin_name: 'TCP/IP Timestamps Supported',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Service detection',
          plugin_id: 42822,
          plugin_name: 'Strict Transport Security (STS) Detection',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 45410,
          plugin_name: "SSL Certificate 'commonName' Mismatch",
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 45590,
          plugin_name: 'Common Platform Enumeration (CPE)',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 54615,
          plugin_name: 'Device Type',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 56984,
          plugin_name: 'SSL / TLS Versions Supported',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 57041,
          plugin_name: 'SSL Perfect Forward Secrecy Cipher Suites Supported',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 62564,
          plugin_name: 'TLS Next Protocols Supported',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 70544,
          plugin_name: 'SSL Cipher Block Chaining Cipher Suites Supported',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 94761,
          plugin_name: 'SSL Root Certification Authority Certificate Information',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 95631,
          plugin_name: 'SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)',
          vulnerability_state: 'Active',
          vpr_score: 5.1,
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Web Servers',
          plugin_id: 106375,
          plugin_name: 'nginx HTTP Server Detection',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Service detection',
          plugin_id: 136318,
          plugin_name: 'TLS Version 1.2 Protocol Detection',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'Service detection',
          plugin_id: 138330,
          plugin_name: 'TLS Version 1.3 Protocol Detection',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        },
        {
          count: 1,
          plugin_family: 'General',
          plugin_id: 156899,
          plugin_name: 'SSL/TLS Recommended Cipher Suites',
          vulnerability_state: 'Active',
          accepted_count: 0,
          recasted_count: 0,
          counts_by_severity: [
            {
              count: 1,
              value: 0
            }
          ],
          cvss_base_score: 0,
          cvss3_base_score: 0,
          severity: 0
        }
      ],
      total_vulnerability_count: 27,
      total_asset_count: 0
    }
  }
};

const data_2 = {
  assets: [
    {
      id: 'a8136321-1660-4610-ae59-21d1f13844ce',
      has_agent: false,
      last_seen: '2022-09-19T17:06:19.618Z',
      last_scan_target: '18.222.120.164',
      sources: [
        {
          name: 'NESSUS_SCAN',
          first_seen: '2022-09-19T17:06:19.618Z',
          last_seen: '2022-09-19T17:06:19.618Z'
        }
      ],
      ipv4: ['18.222.120.164'],
      ipv6: [],
      fqdn: ['ec2-18-222-120-164.us-east-2.compute.amazonaws.com'],
      mac_address: [],
      netbios_name: [],
      operating_system: ['Linux Kernel 2.6'],
      hostname: [],
      agent_name: [],
      aws_ec2_name: [],
      security_protection_level: null,
      security_protections: [],
      exposure_confidence_value: null
    }
  ]
};
