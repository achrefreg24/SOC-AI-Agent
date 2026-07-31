import requests
import json
import time

url = "http://localhost:8000/qualifier-alerte"

# The exact payload from the user (Array of length 1)
payload = [
  {
    "wazuh_alert": {
      "id": "86601",
      "timestamp": "2026-07-27T15:20:00.000+0000",
      "level": 3,
      "description": "Suricata: Alert - test enrichment réel",
      "src_ip": "45.120.216.232",
      "dst_ip": "100.64.0.20",
      "agent": {
        "id": "001",
        "name": "vulnerable-machine-linux",
        "ip": "100.64.0.20"
      },
      "full_raw": {
        "timestamp": "2026-07-27T15:20:00.000+0000",
        "rule": {
          "id": "86601",
          "level": 3,
          "description": "Suricata: Alert - test enrichment réel",
          "groups": [
            "ids",
            "suricata"
          ]
        },
        "agent": {
          "id": "001",
          "name": "vulnerable-machine-linux",
          "ip": "100.64.0.20"
        },
        "data": {
          "srcip": "45.120.216.232",
          "dstip": "100.64.0.20",
          "proto": "TCP"
        },
        "full_log": "Suricata: Alert - test enrichment réel from 45.120.216.232"
      }
    },
    "threat_intelligence": {
      "misp": {
        "found": True,
        "event": {
          "id": "6271",
          "orgc_id": "1",
          "org_id": "1",
          "date": "2026-07-28",
          "threat_level_id": "3",
          "info": "Wazuh Alert [N/A] - Unknown",
          "published": False,
          "uuid": "47d2011c-1d07-4690-b08a-57c6a6cbc9e6",
          "attribute_count": "1",
          "analysis": "0",
          "timestamp": "1785252906",
          "distribution": "0",
          "proposal_email_lock": False,
          "locked": False,
          "publish_timestamp": "0",
          "first_publication": "0",
          "sharing_group_id": "0",
          "disable_correlation": False,
          "extends_uuid": "",
          "protected": None,
          "event_creator_email": "admin@soc.local",
          "Org": {
            "id": "1",
            "name": "ADMIN",
            "uuid": "11487595-097f-4d46-954a-006054728ef3",
            "local": True
          },
          "Orgc": {
            "id": "1",
            "name": "ADMIN",
            "uuid": "11487595-097f-4d46-954a-006054728ef3",
            "local": True
          },
          "Attribute": [
            {
              "id": "9206202",
              "type": "text",
              "category": "External analysis",
              "to_ids": False,
              "uuid": "1d6c6266-4900-488d-bf03-0b9a562ade48",
              "event_id": "6271",
              "distribution": "5",
              "timestamp": "1785252906",
              "comment": "Full Wazuh alert log",
              "sharing_group_id": "0",
              "deleted": False,
              "disable_correlation": False,
              "object_id": "0",
              "object_relation": None,
              "first_seen": None,
              "last_seen": None,
              "value": "No full log available",
              "Galaxy": [],
              "ShadowAttribute": []
            }
          ],
          "ShadowAttribute": [],
          "RelatedEvent": [],
          "Galaxy": [],
          "Object": [],
          "EventReport": [],
          "CryptographicKey": [],
          "Tag": [
            {
              "id": "26988",
              "name": "wazuh",
              "colour": "#b337af",
              "exportable": True,
              "user_id": "0",
              "hide_tag": False,
              "numerical_value": None,
              "is_galaxy": False,
              "is_custom_galaxy": False,
              "local_only": False,
              "local": False,
              "relationship_type": None
            },
            {
              "id": "26989",
              "name": "n8n-auto",
              "colour": "#899d91",
              "exportable": True,
              "user_id": "0",
              "hide_tag": False,
              "numerical_value": None,
              "is_galaxy": False,
              "is_custom_galaxy": False,
              "local_only": False,
              "local": False,
              "relationship_type": None
            },
            {
              "id": "26990",
              "name": "soc-pipeline",
              "colour": "#b22e19",
              "exportable": True,
              "user_id": "0",
              "hide_tag": False,
              "numerical_value": None,
              "is_galaxy": False,
              "is_custom_galaxy": False,
              "local_only": False,
              "local": False,
              "relationship_type": None
            }
          ]
        },
        "attributes": [
          {
            "id": "9206202",
            "type": "text",
            "category": "External analysis",
            "to_ids": False,
            "uuid": "1d6c6266-4900-488d-bf03-0b9a562ade48",
            "event_id": "6271",
            "distribution": "5",
            "timestamp": "1785252906",
            "comment": "Full Wazuh alert log",
            "sharing_group_id": "0",
            "deleted": False,
            "disable_correlation": False,
            "object_id": "0",
            "object_relation": None,
            "first_seen": None,
            "last_seen": None,
            "value": "No full log available",
            "Galaxy": [],
            "ShadowAttribute": []
          }
        ]
      },
      "opencti": {
        "found": False,
        "full_response": {
          "data": {
            "stixCyberObservables": {
              "edges": [
                {
                  "node": {
                    "id": "0aa03ff6-6136-4631-9b98-f5c1df1ca195",
                    "entity_type": "IPv4-Addr",
                    "observable_value": "45.120.216.232",
                    "x_opencti_score": 100,
                    "x_opencti_description": "Agressive IP known malicious on AbuseIPDB - countryCode: HK - abuseConfidenceScore: 100 - lastReportedAt: 2026-07-28T13:02:34+00:00",
                    "created_at": "2026-07-27T13:56:02.659Z",
                    "externalReferences": {
                      "edges": [
                        {
                          "node": {
                            "source_name": "AbuseIPDB database",
                            "url": "https://www.abuseipdb.com/",
                            "description": "AbuseIPDB database URL",
                            "external_id": None
                          }
                        }
                      ]
                    },
                    "indicators": {
                      "edges": [
                        {
                          "node": {
                            "name": "45.120.216.232",
                            "pattern": "[ipv4-addr:value = '45.120.216.232']",
                            "x_opencti_score": 100
                          }
                        }
                      ]
                    },
                    "objectMarking": [
                      {
                        "definition": "TLP:CLEAR",
                        "definition_type": "TLP"
                      }
                    ]
                  }
                }
              ]
            }
          }
        },
        "indicators": []
      }
    },
    "correlation_summary": {
      "total_matches": 1,
      "preliminary_verdict": "intel_found",
      "misp_attributes_count": 1,
      "opencti_indicators_count": 0
    },
    "analysis_request": {
      "task": "Analyze this security alert and determine if it's a TRUE POSITIVE or FALSE POSITIVE",
      "context": {
        "source": "Wazuh SIEM alert enriched with MISP and OpenCTI threat intelligence",
        "goal": "Provide actionable security analysis"
      }
    }
  }
]

print("Envoi du test via requete HTTP locale a FastAPI...")
try:
    response = requests.post(url, json=payload, timeout=300)
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2, ensure_ascii=False))
except Exception as e:
    print(f"Erreur HTTP: {e}")
