#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#


ONE_MASTER = {
    'ipa.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "ipa.ipa.example",
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
            ]
          }
        },
        # No RUV's on a freshly installed master
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
            }
        },
    ]
}


THREE_MASTERS_OK = {
    'ipa.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "ipa.ipa.example",
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "4"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "6"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "KnownRUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "ruvs_dc=ipa,dc=example",
              "suffix": "dc=ipa,dc=example",
              "ruvs": [
                [
                  "ipa.ipa.example",
                  "4"
                ],
                [
                  "replica2.ipa.example",
                  "7"
                ],
                [
                  "replica1.ipa.example",
                  "3"
                ]
              ]
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica2.ipa.example",
                "8"
              ],
              [
                "replica1.ipa.example",
                "5"
              ]
            ]
          }
        }
    ],
    'replica1.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "replica1.ipa.example",
              "masters": [
                "ipa.ipa.example",
                "replica1.ipa.example",
                "replica2.ipa.example",
              ],
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "3"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "5"
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_dc=ipa,dc=example",
            "suffix": "dc=ipa,dc=example",
            "ruvs": [
              [
                "replica1.ipa.example",
                "3"
              ],
              [
                "ipa.ipa.example",
                "4"
              ],
              [
                "replica2.ipa.example",
                "7"
              ]
            ]
          }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "replica1.ipa.example",
                "5"
              ],
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica2.ipa.example",
                "8"
              ]
            ]
          }
        }
    ],
    'replica2.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "replica2.ipa.example",
              "masters": [
                "ipa.ipa.example",
                "replica1.ipa.example",
                "replica2.ipa.example",
              ],
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "7"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "8"
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_dc=ipa,dc=example",
            "suffix": "dc=ipa,dc=example",
            "ruvs": [
              [
                "replica2.ipa.example",
                "7"
              ],
              [
                "ipa.ipa.example",
                "4"
              ],
              [
                "replica1.ipa.example",
                "3"
              ]
            ]
          }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "replica2.ipa.example",
                "8"
              ],
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica1.ipa.example",
                "5"
              ]
            ]
          }
        }
    ]
}


#
# Same three masters but replica1 has an extra RUV value
#
THREE_MASTERS_BAD_IPA_RUV = {
    'ipa.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "ipa.ipa.example",
              "masters": [
                "ipa.ipa.example",
                "replica1.ipa.example",
                "replica2.ipa.example",
              ],
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "4"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "6"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "KnownRUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "ruvs_dc=ipa,dc=example",
              "suffix": "dc=ipa,dc=example",
              "ruvs": [
                [
                  "ipa.ipa.example",
                  "4"
                ],
                [
                  "replica2.ipa.example",
                  "7"
                ],
                [
                  "replica1.ipa.example",
                  "3"
                ],
                [
                  "replica1.ipa.example",
                  "9"
                ]
              ]
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica2.ipa.example",
                "8"
              ],
              [
                "replica1.ipa.example",
                "5"
              ]
            ]
          }
        }
    ],
    'replica1.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "replica1.ipa.example",
              "masters": [
                "ipa.ipa.example",
                "replica1.ipa.example",
                "replica2.ipa.example",
              ],
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "3"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "5"
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_dc=ipa,dc=example",
            "suffix": "dc=ipa,dc=example",
            "ruvs": [
              [
                "replica1.ipa.example",
                "3"
              ],
              [
                "ipa.ipa.example",
                "4"
              ],
              [
                "replica2.ipa.example",
                "7"
              ]
            ]
          }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "replica1.ipa.example",
                "5"
              ],
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica2.ipa.example",
                "8"
              ]
            ]
          }
        }
    ],
    'replica2.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "replica2.ipa.example",
              "masters": [
                "ipa.ipa.example",
                "replica1.ipa.example",
                "replica2.ipa.example",
              ],
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "7"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "8"
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_dc=ipa,dc=example",
            "suffix": "dc=ipa,dc=example",
            "ruvs": [
              [
                "replica2.ipa.example",
                "7"
              ],
              [
                "ipa.ipa.example",
                "4"
              ],
              [
                "replica1.ipa.example",
                "3"
              ]
            ]
          }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "replica2.ipa.example",
                "8"
              ],
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica1.ipa.example",
                "5"
              ]
            ]
          }
        }
    ]
}


#
# Same three masters but replica2 CA has an extra RUV value
#
THREE_MASTERS_BAD_CS_RUV = {
    'ipa.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "ipa.ipa.example",
              "masters": [
                "ipa.ipa.example",
                "replica1.ipa.example",
                "replica2.ipa.example",
              ],
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "4"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "6"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "KnownRUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "ruvs_dc=ipa,dc=example",
              "suffix": "dc=ipa,dc=example",
              "ruvs": [
                [
                  "ipa.ipa.example",
                  "4"
                ],
                [
                  "replica2.ipa.example",
                  "7"
                ],
                [
                  "replica1.ipa.example",
                  "3"
                ],
              ]
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica2.ipa.example",
                "8"
              ],
              [
                "replica1.ipa.example",
                "5"
              ]
            ]
          }
        }
    ],
    'replica1.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "replica1.ipa.example",
              "masters": [
                "ipa.ipa.example",
                "replica1.ipa.example",
                "replica2.ipa.example",
              ],
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "3"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "5"
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_dc=ipa,dc=example",
            "suffix": "dc=ipa,dc=example",
            "ruvs": [
              [
                "replica1.ipa.example",
                "3"
              ],
              [
                "ipa.ipa.example",
                "4"
              ],
              [
                "replica2.ipa.example",
                "7"
              ]
            ]
          }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "replica1.ipa.example",
                "5"
              ],
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica2.ipa.example",
                "8"
              ]
            ]
          }
        }
    ],
    'replica2.ipa.example': [
        {
            "source": "ipahealthcheck.meta.core",
            "check": "MetaCheck",
            "result": "SUCCESS",
            "kw": {
              "fqdn": "replica2.ipa.example",
              "masters": [
                "ipa.ipa.example",
                "replica1.ipa.example",
                "replica2.ipa.example",
              ],
              "ipa_version": "4.8.4",
              "ipa_api_version": "2.235"
            }
        },
        {
          "source": "ipahealthcheck.ipa.meta",
          "check": "IPAMetaCheck",
          "result": "SUCCESS",
          "kw": {
            "masters": [
              "ipa.ipa.example",
              "replica1.ipa.example",
              "replica2.ipa.example"
            ]
          }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "dc=ipa,dc=example",
              "ruv": "7"
            }
        },
        {
            "source": "ipahealthcheck.ds.ruv",
            "check": "RUVCheck",
            "result": "SUCCESS",
            "kw": {
              "key": "o=ipaca",
              "ruv": "8"
            }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_dc=ipa,dc=example",
            "suffix": "dc=ipa,dc=example",
            "ruvs": [
              [
                "replica2.ipa.example",
                "7"
              ],
              [
                "ipa.ipa.example",
                "4"
              ],
              [
                "replica1.ipa.example",
                "3"
              ]
            ]
          }
        },
        {
          "source": "ipahealthcheck.ds.ruv",
          "check": "KnownRUVCheck",
          "result": "SUCCESS",
          "kw": {
            "key": "ruvs_o=ipaca",
            "suffix": "o=ipaca",
            "ruvs": [
              [
                "replica2.ipa.example",
                "8"
              ],
              [
                "ipa.ipa.example",
                "6"
              ],
              [
                "replica1.ipa.example",
                "5"
              ],
              [
                "replica1.ipa.example",
                "9"
              ]
            ]
          }
        }
    ]
}
