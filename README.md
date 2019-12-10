# What is healthcheck?

It is an attempt to answer the question "Is my IPA installation working properly."

Major pain points in an IPA installation were identified and tests written to verify that the system is configured or running with expected settings.

The major areas currently covered are:

* Certificate configuration and expiration dates
* Replication errors
* Replication topology
* AD Trust configuration
* Service status
* File permissions of important configuration files
* File system space

# How to use it?

The simplest way to use Healthcheck is to run it from the command-line as root as ipa-healthcheck. Running from the command-line will display the output to the console unless --output-file=FILENAME is used.
There is output for _all_ tests so we can be sure that an error condition isn't providing a false positive. The command-line option --failures-only will skip printing the SUCCESS conditions.

To automate running Healthcheck every day a systemd timer can be used. 
The default destination directory for healthcheck logs is `/var/log/ipa/healthcheck` and this can be the input into a monitoring system to track changes over time or to alert if a test goes from working to error or warning.

A systemd timer is provided but is not enabled by default. To enable it:

    # systemctl enable ipa-healthcheck.timer
    # systemctl start ipa-healthcheck.timer

logrotate will handle log rotation and keep up to 30 days of history.
This can be configured via the `/etc/logrotate.d/ipahealthcheck` file.


If using upstream or if your distribution's package does not include the timer, it can be installed manually as follows.

First create the destination log directory:

    # mkdir /var/log/ipa/healthcheck

Then copy the systemd configuration into place:

    # cp systemd/ipa-healthcheck.timer /usr/lib/systemd/system
    # cp systemd/ipa-healthcheck.service /usr/lib/systemd/system

Put a shell script in place to do the invocation:

    # cp systemd/ipa-healthcheck.sh /usr/libexec/ipa

Tell systemd about it and enable it:

    # systemctl daemon-reload
    # systemctl enable ipa-healthcheck.timer
    # systemctl start ipa-healthcheck.timer

Finally add a proper logrotate configuration:

    # cp logrotate/ipahealthcheck /etc/logrotate.d/

Note that logrotate requires crond to be started+enabled.

To test:

    # systemctl start ipa-healthcheck


# What if I get an error or warning?

In general the output should contain enough information to provide a basic idea of why it is considered an error. If a specific value is expected then that will be provided along with the observed value. For example a number of files are checked for owner, group and permissions. If a value differs from the expected value then the expected and got values will be reported.

Running from the command-line will aid in ensuring that the condition is correct to what is expected. The basic idea is that it would be iterative:

1. ipa-healthcheck
2. manually address any errors

Repeat until until no errors are reported.

# What about false positives?

It is possible that some tests will need to be tweaked to accommodate real world situations. If you observe false positives then please open an issue at [https://github.com/freeipa/freeipa-healthcheck/issues](URL)

There is no way to suppress an error without making a change either in the test or in the system to accommodate the test requirements.

# Organization

In order to gauge the health of a system one needs to check any number of things.

These things, or checks, can be logically grouped together. This is a source. A source consists of 1..n checks.

A check should be as atomic as possible to limit the scope and complexity, ideally returning a yes/no whether the check passes or fails. This is not always possible and that's ok.

At a higher level than source is product. The hierarchy looks like:

    ipahealthcheck
      product
        source
          check
          check
          ...
        source
          check
          ...

A source provides a registry so its checks are discoverable.

# Writing a check module

The base class for a check is ipahealthcheck.core.plugin::Plugin

The only method that needs to be implemented is check(). This implements the test against the system and should yield a Result object. Because check() is a generator multiple results can be yielded from a single check.

Typically each source defines its own plugin.py which contains the registry. This looks like:



        from ipahealthcheck.core.plugin import Registry

        registry = Registry()

A basic check module consists of:

        from ipahealthcheck.core.plugin import Plugin, Result
        from ipahealthcheck.core import constants
        from ipahealthcheck.mymodule.plugin import registry


        @registry
        class MyPlugin(Plugin):
            def check(self):
                yield Result(self, constants.SUCCESS)

# Return value

A check yields a Result. This contains the outcome of the check including:

* result as defined in ipahealthcheck/core/constants.py
* kw, a python dictionary of name value pairs that provide details on the error

The kw dict is meant to provide context for the check. Err on the side of
too much information.

Some predefined keys of the kw dictionary are:

* key: some checks can have multiple tests. This provides for uniqueuess.
* msg: A message that can take other keywords as input
* exception: used when a check raises an exception

kw is optional if result is SUCCESS.

If a check consist of only a single test then it is not required to yield
a Result, one marking the check as successful will be added automatically.

If a check is complex enough that it checks multiple values then it should
yield a SUCCESS Result() for each one.

A Result is required for every test done so that one can know that the
check was executed.

The run time duration of each check will be calculated. The mechanism
differs depending on complexity.

A check should normally use the @duration decorator to track the
duration it took to execute the check.


        @registry
        class MyPlugin(Plugin):
            @duration
            def check(self):
                yield Result(self, constants.SUCCESS)


# Registering a source

The list of sources is stored in setup.py in the top-level of the tree.

Assuming it is contained in-tree it takes the form of:

'ipahealthcheck.<dir>': [
    'name = ipahealthcheck.<dir>.<file>'
]

For example, to add replication to the src/ipahealthcheck/ipa directory

    'ipahealthcheck.ipa': [
        'ipacerts = ipahealthcheck.ipa.certs',
        'ipafiles = ipahealthcheck.ipa.files',
        'ipakerberos = ipahealthcheck.ipa.kerberos',
        'replication = ipahealthcheck.ipa.replication',
    ],

If a new branch of sources is added a new registry is needed. This is
added into the ipahealthcheck.registry section in setup.py. If we decided
that replication didn't belong under ipahealthcheck.ipa but instead in
ipahealthcheck.ds it would look like:

    'ipahealthcheck.registry': [
        'ipahealthcheck.ipa = ipahealthcheck.ipa.plugin:registry',
        'ipahealthcheck.dogtag = ipahealthcheck.dogtag.plugin:registry',
        'ipahealthcheck.meta = ipahealthcheck.meta.plugin:registry',
        'ipahealthcheck.ds = ipahealthcheck.ds.plugin:registry',
    ],

and

    'ipahealthcheck.ds': [
        'replication = ipahealthcheck.ds.replication',
    ],

# Execution

It is possible to execute a single check or all checks in a single source by passing --source and/or --check on the command-line. This is intended to help user's quickly ensure that something is fixed by re-running a check after making a change.

# Output

Output is controlled via Output plugins. These take the global Results object and iterate over it to produce output in the desired format. The result is returned as a string.

A custom Output class must implement the generate method which generates the output.

A bare-bones output class is:

        @output_registry
        class Basic(Output):
            def generate(self, data):
                output = [x for x in data.output()]

                return output

An output object can declare its own options by adding a tuple named options to the class in the form of (arg_name, dict(argparse options).

An example to provide an option to indent the text to make it more readable.

        options = (
            (--indent', dict(dest='indent', help='How deeply to indent')),
        )

# Meta

The meta source is intended to collect basic information about the run such as the host it is run on and the time it was run.

# Useful to diagnose a failed installation?

No. healthcheck compares a known state to the state of the installation. If the installation failed then you are guaranteed to get a ton of false positives and all it will tell you is that your installation failed.

# Testing and development

The package can be tested and developed in a python virtual environment.

It requires a full freeIPA deployment so full set of system packages
need to be installed and an IPA master running.

To create the virtual environment run:

    % python3 -m venv --system-site-packages venv
    % venv/bin/pip install -e .

To use the environment

    % source venv/bin/activate

To run the healthchecks (must be done as root for proper results):

    # source venv/bin/activate
    # ipa-healthcheck

To run the tests execute the virtual environment:

    % pip install pytest
    % pytest

The configuration file and directory are not yet created so you'll need
to do that manually:

    # mkdir /etc/ipahealthcheck
    # echo "[default]" > /etc/ipahealthcheck/ipahealthcheck.conf

# Understanding the results

Here is some basic guidance on what a non-SUCCESS message from a check means. How to fix any particular result is heavily dependent on the error(s) discovered and their context. A single failure may be detected by multiple checks.

## ipahealthcheck.dogtag.ca

### DogtagCertsConfigCheck
Compares the value of the CA (and KRA if installed) certificates with the value found in CS.cfg. If they don't match then the CA will likely fail to start.

    {
      "source": "ipahealthcheck.dogtag.ca",
      "check": "DogtagCertsConfigCheck",
      "result": "ERROR",
      "kw": {
        "key": "ocspSigningCert cert-pki-ca",
        "directive": "ca.ocsp_signing.cert",
        "configfile": "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg",
        "msg": "Certificate 'ocspSigningCert cert-pki-ca' does not match the value of ca.ocsp_signing.cert in /var/lib/pki/pki-tomcat/conf/ca/CS.cfg"
        }
    }

### DogtagCertsConnectivityCheck
Runs the equivalent of ipa cert-show 1 to verify basic connectivity.

    {
      "source": "ipahealthcheck.dogtag.ca",
      "check": "DogtagCertsConnectivityCheck",
      "result": "ERROR",
      "kw": {
        "msg": "Request for certificate failed, Certificate operation cannot be completed: Unable to communicate with CMS (503)"
      }
    }

## ipahealthcheck.ds.replication

### ReplicationConflictCheck
Searches for entries in LDAP matching (&(!(objectclass=nstombstone))(nsds5ReplConflict=*))

    {
      "source": "ipahealthcheck.ds.replication",
      "check": "ReplicationConflictCheck",
      "result": "ERROR",
      "kw": {
        "key": "nsuniqueid=66446001-1dd211b2+uid=bjenkins,cn=users,cn=accounts,dc=example,dc=test",
        "conflict": "namingConflict",
        "msg": "Replication conflict"
      }
    }

## ipahealthcheck.ipa.certs

### IPACertmongerExpirationCheck
Loops through all expected certmonger requests and checks expiration based on what certmonger knows about the certificate. A warning is issued if the certificate expires in cert_expiration_days (the default is 28).

Expired certificate:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertmongerExpirationCheck",
      "result": "ERROR",
      "kw": {
        "key": 1234,
        "expiration_date", "20160101001704Z",
        "msg": "Request id 1234 expired on 20160101001704Z"
      }
    }

Expiring certificate:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertmongerExpirationCheck",
      "result": "WARNING",
      "kw": {
        "key": 1234,
        "expiration_date", "20160101001704Z",
        "days": 9,
        "msg": "Request id 1234 expires in 9 days"
      }
    }

### IPACertfileExpirationCheck
Similar to IPACertmongerExpirationCheck except the certificate is pulled from the PEM file or NSS database and re-verified. This is in case the certmonger tracking becomes out-of-sync with the certificate on disk.

The certificate file cannot be opened:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertfileExpirationCheck",
      "result": "ERROR",
      "kw": {
        "key": 1234,
        "certfile": "/path/to/cert.pem",
        "error": [error],
        "msg": "Unable to open cert file '/path/to/cert.pem': [error]"
      }
    }

The NSS database cannot be opened:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertfileExpirationCheck",
      "result": "ERROR",
      "kw": {
        "key": 1234,
        "dbdir": "/path/to/nssdb",
        "error": [error],
        "msg": "Unable to open NSS database '/path/to/nssdb': [error]"
      }
    }

The tracked nickname cannot be found in the NSS database:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertfileExpirationCheck",
      "result": "ERROR",
      "kw": {
        "key": 1234,
        "dbdir": "/path/to/nssdb",
        "nickname": [nickname],
        "error": [error],
        "msg": "Unable to retrieve cert '[nickname]' from '/path/to/nssdb': [error]"
      }
    }

Expired certificate:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertfileExpirationCheck",
      "result": "ERROR",
      "kw": {
        "key": 1234,
        "expiration_date", "20160101001704Z",
        "msg": "Request id 1234 expired on 20160101001704Z"
      }
    }

Expiring certificate:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertfileExpirationCheck",
      "result": "WARNING",
      "kw": {
        "key": 1234,
        "expiration_date", "20160101001704Z",
        "days": 9,
        "msg": "Request id 1234 expires in 9 days"
      }
    }

### IPACAChainExpirationCheck

Load the CA chain from /etc/ipa/ca.crt and test each one for expiration. This test is designed to ensure that the entire CA chain for all certificates is validated. For example, if the web or LDAP certificates have been replaced then the CA chain for those certs will reside in /etc/ipa/ca.crt. This includes an IPA CA signed by an external authority.

Expiring certificate:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACAChainExpirationCheck",
      "result": "WARNING",
      "kw": {
        "path": "/etc/ipa/ca.crt",
        "key": "CN=Certificate Authority,O=EXAMPLE.TEST",
        "days": 2,
        "msg": "CA '{key}' is expiring in {days} days."
      }
    }

Expired certificate:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACAChainExpirationCheck",
      "result": "CRITICAL",
      "kw": {
        "path": "/etc/ipa/ca.crt",
        "key": "CN=Certificate Authority,O=EXAMPLE.TEST",
        "msg": "CA '{key}' is expired."
      }
    }


### IPACertTracking
Compares the certmonger tracking on the system to the expected values. A query of the expected name/value pairs in certmonger is done to certmonger. On failure the contents of the query are missing. This result would be seen either if the certificate is tracked but there is some slight change in the expected value or if the tracking is missing entirely.

Missing certificate tracking:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertTracking",
      "result": "ERROR",
      "kw": {
        "key": "cert-file=/var/lib/ipa/ra-agent.pem, key-file=/var/lib/ipa/ra-agent.key, ca-name=dogtag-ipa-ca-renew-agent, cert-storage=FILE, cert-presave-command=/usr/libexec/ipa/certmonger/renew_ra_cert_pre,  cert-postsave-command=/usr/libexec/ipa/certmonger/renew_ra_cert"
        "msg": "Missing tracking for cert-file=/var/lib/ipa/ra-agent.pem, key-file=/var/lib/ipa/ra-agent.key, ca-name=dogtag-ipa-ca-renew-agent, cert-storage=FILE, cert-presave-command=/usr/libexec/ipa/certmonger/renew_ra_cert_pre,  cert-postsave-command=/usr/libexec/ipa/certmonger/renew_ra_cert"
      }
    }

An unknown certificate is being tracked by certmonger. This may be perfectly legitimate, it is provided for information only:

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertTracking",
      "result": "WARNING",
      "kw": {
        "key": 1234,
        "msg": "Unknown certmonger id 1234'
      }
    }

### IPACertNSSTrust
The trust for certificates stored in NSS databases is compared against a known good state.

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertNSSTrust",
      "result": "ERROR",
      "kw": {
        "key": "auditSigningCert cert-pki-ca",
        "expected": "u,u,Pu",
        "got": "u,u,u",
        "nickname": "auditSigningCert cert-pki-ca",
        "dbdir": "/etc/pki/pki-tomcat/alias",
        "msg": "Incorrect NSS trust for auditSigningCert cert-pki-ca. Got u,u,u expected u,u,Pu"
      }
    }

### IPANSSChainValidation
Validate the certificate chain of the NSS certificates. This executes: certutil -V -u V -e -d [dbdir] -n [nickname].

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPANSSChainValidation",
      "result": "ERROR",
      "kw": {
        "key": "/etc/dirsrv/slapd-EXAMPLE-TEST:Server-Cert",
        "nickname": "Server-Cert",
        "dbdir": [path to NSS database],
        "reason": "certutil: certificate is invalid: Peer's Certificate issuer is not recognized.\n: ",
        "msg": ""Validation of Server-Cert in /etc/dirsrv/slapd-EXAMPLE-TEST/ failed: certutil: certificate is invalid: Peer's Certificate issuer is not recognized.\n "
      }
    }

### IPAOpenSSLChainValidation
Validate the certificate chain of the OpenSSL certificates. This executes: openssl verify -verbose -show_chain -CAfile /etc/ipa/ca.crt /path/to/cert.pem

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPAOpenSSLChainValidation",
      "result": "ERROR",
      "kw": {
        "key": "/var/lib/ipa/ra-agent.pem",
        "reason": "O = EXAMPLE.TEST, CN = IPA RA\nerror 20 at 0 depth lookup: unable to get local issuer certificate\n",
        "msg": "Certificate validation for /var/lib/ipa/ra-agent.pem failed: O = EXAMPLE.TEST, CN = IPA RA\nerror 20 at 0 depth lookup: unable to get local issuer certificate\n"
      }
    }

### IPARAAgent
Verify the description and userCertificate values in uid=ipara,ou=People,o=ipaca.

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPARAAgent",
      "result": "ERROR",
      "kw": {
        "expected": "2;125;CN=Certificate Authority,O=EXAMPLE.TEST;CN=IPA RA,O=EXAMPLE.TEST",
        "got": "2;7;CN=Certificate Authority,O=EXAMPLE.TEST;CN=IPA RA,O=EXAMPLE.TEST",
        "msg": "RA agent description does not match 2;7;CN=Certificate Authority,O=EXAMPLE.TEST;CN=IPA RA,O=EXAMPLE.TEST in LDAP and expected 2;125;CN=Certificate Authority,O=EXAMPLE.TEST;CN=IPA RA,O=EXAMPLE.TEST"
      }
    }

### IPACertRevocation
Confirm that the IPA certificates are not revoked. This uses the certmonger tracking to determine the list of certificates to validate.

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertRevocation",
      "result": "ERROR",
      "kw": {
        "key": 1234,
        "revocation_reason": "superseded",
        "msg": "Certificate is revoked, superseded"
      }
    }

### IPACertmongerCA
Check that the certmonger CA configuration is correct. Evaluates dogtag-ipa-ca-renew-agent and dogtag-ipa-ca-renew-agent-reuse.

    {
      "source": "ipahealthcheck.ipa.certs",
      "check": "IPACertmongerCA",
      "result": "ERROR",
      "kw": {
        "key": "dogtag-ipa-ca-renew-agent",
        "msg": "Certmonger CA 'dogtag-ipa-ca-renew-agent' missing"
      }
    }

## ipahealthcheck.ipa.dna

### IPADNARangeCheck
This reports the configured DNA range, if any. It is expected that this is combined elsewhere for further analysis.

    {
      "source": "ipahealthcheck.ipa.dna",
      "check": "IPADNARangeCheck",
      "result": "SUCCESS",
      "kw": {
        "range_start": 1000,
        "range_max": 199999,
        "next_start": 0,
        "next_max": 0,
      }
    }

## ipahealthcheck.ipa.files

These checks verify the owner and mode of files installed or configured by IPA. There are many permutations of file permissions and ownership that may be valid and continue to work. This reports on the expected values in a fresh IPA installation. Deviations are reported at the WARNING level.

This covers the following checks:

### IPAFileNSSDBCheck
### IPAFileCheck
### TomcatFileCheck

Examples include:

    {
      "source": "ipahealthcheck.ipa.files",
      "check": "IPAFileCheck",
      "result": "WARNING",
      "kw": {
        "key": "_etc_ipa_ca.crt_mode",
        "path": "/etc/ipa/ca.crt",
        "type": "mode",
        "expected": "0644",
        "got": "0444",
        "msg": "Permissions of /etc/ipa/ca.crt are 0444 and should be 0644"
      }
    }

    {
      "source": "ipahealthcheck.ipa.files",
      "check": "IPAFileNSSDBCheck",
      "result": "WARNING",
      "kw": {
        "key": "_etc_dirsrv_slapd-EXAMPLE-TEST_pkcs11.txt_mode",
        "path": "/etc/dirsrv/slapd-EXAMPLE-TEST/pkcs11.txt",
        "type": "mode",
        "expected": "0640",
        "got": "0666",
        "msg": "Permissions of /etc/dirsrv/slapd-EXAMPLE-TEST/pkcs11.txt are 0666 and should be 0640"
      }
    },

## ipahealthcheck.ipa.host

### IPAHostKeytab

Executes: kinit -kt /etc/krb5.keytab to verify that the host keytab is valid.

## ipahealthcheck.ipa.roles

A set of information checks to report on whether the current master is the CRL generator and/or the renewal master.

### IPACRLManagerCheck

    {
      "source": "ipahealthcheck.ipa.roles",
      "check": "IPACRLManagerCheck",
      "result": "SUCCESS",
      "kw": {
        "key": "crl_manager",
        "crlgen_enabled": true
      }
    },

### IPARenewalMasterCheck

    {
      "source": "ipahealthcheck.ipa.roles",
      "check": "IPARenewalMasterCheck",
      "result": "SUCCESS",
      "kw": {
        "key": "renewal_master",
        "master": true
      }
    }

## ipahealthcheck.ipa.topology

Topology checks to check both for compliance with recommendations and errors.

### IPATopologyDomainCheck

Provide the equivalent of: ipa topologysuffix-verify <domain>

On failure this will return any errors discovered like connection errors or too many replication agreements.

On success it will return the configured domains.

    {
      "source": "ipahealthcheck.ipa.topology",
      "check": "IPATopologyDomainCheck",
      "result": "SUCCESS",
      "kw": {
        "suffix": "domain"
      }
    },
    {
      "source": "ipahealthcheck.ipa.topology",
      "check": "IPATopologyDomainCheck",
      "result": "SUCCESS",
      "kw": {
        "suffix": "ca"
      }
    }

## ipahealthcheck.ipa.trust

Verify common AD Trust configuration issues. Checks will return SUCCESS if not configured as a trust agent or controller.

### IPATrustAgentCheck

Check the sssd configuration when the machine is configured as a trust agent.

provider should be ipa and ipa_server_mode should be true.

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPATrustAgentCheck",
      "severity": ERROR,
      "kw": {
        "key": "ipa_server_mode_false",
        "attr": "ipa_server_mode",
        "sssd_config": "/etc/sssd/sssd.conf",
        "domain": "ipa.example.com",
        "msg": "{attr} is not True in {sssd_config} in the domain {domain}"
      }
    }

### IPATrustDomainsCheck

Ensure that the IPA domain is in the output of sssctl domain-list and the trust domains matches the sssd domains.

If the domain lists don't match:

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPATrustDomainsCheck",
      "result": "ERROR",
      "kw": {
        "key": "domain-list",
        "sslctl": "/usr/sbin/sssctl",
        "sssd_domains": "ad.vm",
        "trust_domains": "",
        "msg": "{sslctl} {key} reports mismatch: sssd domains {sssd_domains} trust domains {trust_domains}"
      }
    }

### IPATrustCatalogCheck

This resolves an AD user, Administrator@REALM. This populates the AD Global catalog and AD Domain Controller values in sssctl domain-status output.

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPATrustCatalogCheck",
      "result": "ERROR",
      "kw": {
        "key": "AD Global Catalog",
        "output": "Active servers:\nAD Domain Controller: root-dc.ad.vm\nIPA: ipa.example.com",
        "sssctl": "/usr/sbin/sssctl",
        "domain": "ad.vm",
        "msg": "{key} not found in {sssctl} 'domain-status' output: {output}"
      }
    }

### IPAsidgenpluginCheck

Verifies that the sidgen plugin is enabled in the IPA 389-ds instance.

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPAsidgenpluginCheck",
      "result": "ERROR",
      "kw": {
        "key": "IPA SIDGEN",
        "error": "no such entry",
        "msg": "Error retrieving 389-ds plugin {key}: {error}"
      }
    }
### IPATrustAgentMemberCheck

Verify that the current host is a member of cn=adtrust agents,cn=sysaccounts,cn=etc,SUFFIX.

  {
    "source": "ipahealthcheck.ipa.trust",
    "check": "IPATrustAgentMemberCheck",
    "result": "ERROR",
    "kw": {
      "key": "ipa.example.com",
      "group": "adtrust agents",
      "msg": "{key} is not a member of {group}"
    }
  }

### IPATrustControllerPrincipalCheck

Verify that the current host cifs principal is a member of cn=adtrust agents,cn=sysaccounts,cn=etc,SUFFIX.

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPATrustControllerPrincipalCheck",
      "result": "ERROR",
      "kw": {
        "key": "cifs/ipa.example.com@EXAMPLE.COM",
        "group": "adtrust agents",
        "msg": "{key} is not a member of {group}"
      }
    }

### IPATrustControllerServiceCheck

Verify that the current host starts the ADTRUST service in ipactl.

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPATrustControllerServiceCheck",
      "result": "ERROR",
      "kw": {
        "key": "ADTRUST",
        "msg": "{key} service is not enabled"
      }
    }

### IPATrustControllerConfCheck

Verify that ldapi is enabled for the passdb backend in the output of net conf list:

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPATrustControllerConfCheck",
      "result": "ERROR",
      "kw": {
        "key": "net conf list",
        "got": "",
        "expected": "ipasam:ldapi://%2fvar%2frun%2fslapd-EXAMPLE-COM.socket",
        "option": "passdb backend",
        "msg": "{key} option {option} value {got} doesn't match expected value {expected}"
      }
    }

### IPATrustControllerGroupSIDCheck

Verify that the admins group's SID ends with 512 (Domain Admins RID).

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPATrustControllerGroupSIDCheck",
      "result": "ERROR",
      "kw": {
        "key": "ipantsecurityidentifier",
        "rid": "S-1-5-21-1078564529-1875285547-1976041503-513",
        "msg": "{key} is not a Domain Admins RID"
      }
    }

### IPATrustPackageCheck

If not a trust controller and AD trust is enabled verify that the trust-ad pkg is installed.

    {
      "source": "ipahealthcheck.ipa.trust",
      "check": "IPATrustPackageCheck",
      "result": "WARNING",
      "kw": {
        "key": "adtrustpackage",
        "msg": "trust-ad sub-package is not installed. Administration will be limited."
      }
    }

## ipahealthcheck.meta.services

Return the status of required IPA services

The following services are monitored:

  * certmonger
  * dirsrv
  * gssproxy
  * httpd
  * ipa_custodia
  * ipa_dnskeysyncd
  * ipa_otpd
  * kadmin
  * krb5kdc
  * named
  * pki_tomcatd
  * sssd

The value of check is the name of the IPA service. Note that dashes are replaced with underscores in the service names.

An example of a stopped service:

    {
      "source": "ipahealthcheck.meta.services",
      "check": "httpd",
      "result": "ERROR",
      "kw": {
        "status": false,
        "msg": "httpd: not running"
      }
    }

## ipahealthcheck.meta.core

Provide basic information about the IPA master itself.

### MetaCheck

Output includes the FQDN and the version of IPA.

    {
      "source": "ipahealthcheck.meta.core",
      "check": "MetaCheck",
      "result": "SUCCESS",
      "kw": {
        "fqdn": "ipa.example.test",
        "ipa_version": "4.8.0",
        "ipa_api_version": "2.233"
      }
    }

## ipahealthcheck.system.filesystemspace

Check on available disk space. Running low can cause issues with logging, execution and backups.

### FileSystemSpaceCheck

Both a percentage and raw minimum values are tested.

It is possible there is some overlap depending on mount points.

The minimum free is 20 percent and is currently hard coded.

The following paths are checked:

Path                    free MB
/var/lib/dirsrv/        1024
/var/lib/ipa/backup/    512
/var/log/               1024
/var/log/audit/         512
/var/tmp/               512
/tmp                    512

For example a full /tmp would be reported as:

    {
      "source": "ipahealthcheck.system.filesystemspace",
      "check": "FileSystemSpaceCheck",
      "result": "ERROR",
      "kw": {
        "msg": "/tmp: free space percentage under threshold: 0% < 20%",
        "store": "/tmp",
        "percent_free": 0,
        "threshold": 20
      }
    },
    {
      "source": "ipahealthcheck.system.filesystemspace",
      "check": "FileSystemSpaceCheck",
      "result": "ERROR",
      "kw": {
        "msg": "/tmp: free space under threshold: 0 MiB < 512 MiB",
        "store": "/tmp",
        "free_space": 0,
        "threshold": 512
      }
    }

