from setuptools import find_packages, setup


setup(
    name='ipahealthcheck',
    version='0.19',
    package_dir={'': 'src'},
    # packages=find_packages(where='src'),
    packages=[
        'ipahealthcheck.core',
        'ipahealthcheck.dogtag',
        'ipahealthcheck.ds',
        'ipahealthcheck.ipa',
        'ipahealthcheck.meta',
        'ipahealthcheck.system',
        'ipaclustercheck.core',
        'ipaclustercheck.ipa',
    ],
    # Add importlib-metadata for Python < 3.8 compatibility
    install_requires=[
        'importlib-metadata>=1.0; python_version<"3.8"',
    ],
    entry_points={
        # creates bin/ipahealthcheck
        'console_scripts': [
            'ipa-healthcheck = ipahealthcheck.core.main:main',
            'ipa-clustercheck = ipaclustercheck.core.main:main',
        ],
        # subsystem registries
        'ipahealthcheck.registry': [
            'ipahealthcheck.dogtag = ipahealthcheck.dogtag.plugin:registry',
            'ipahealthcheck.ipa = ipahealthcheck.ipa.plugin:registry',
            'ipahealthcheck.meta = ipahealthcheck.meta.plugin:registry',
            'ipahealthcheck.ds = ipahealthcheck.ds.plugin:registry',
            'ipahealthcheck.system = ipahealthcheck.system.plugin:registry'
        ],
        # plugin modules for ipahealthcheck.meta registry
        'ipahealthcheck.meta': [
            'meta = ipahealthcheck.meta.core',
            'services = ipahealthcheck.meta.services',
        ],
        # plugin modules for ipahealthcheck.ipa registry
        'ipahealthcheck.ipa': [
            'ipacerts = ipahealthcheck.ipa.certs',
            'ipaconfig = ipahealthcheck.ipa.config',
            'ipadna = ipahealthcheck.ipa.dna',
            'ipadns = ipahealthcheck.ipa.idns',
            'ipafiles = ipahealthcheck.ipa.files',
            'ipahost = ipahealthcheck.ipa.host',
            'ipakdc = ipahealthcheck.ipa.kdc',
            'ipaproxy = ipahealthcheck.ipa.proxy',
            'ipameta = ipahealthcheck.ipa.meta',
            'ipanss = ipahealthcheck.ipa.nss',
            'iparoles = ipahealthcheck.ipa.roles',
            'ipatopology = ipahealthcheck.ipa.topology',
            'ipatrust = ipahealthcheck.ipa.trust',
        ],
        # plugin modules for ipahealthcheck.dogtag registry
        'ipahealthcheck.dogtag': [
            'dogtagca = ipahealthcheck.dogtag.ca',
        ],
        # plugin modules for ipahealthcheck.ds registry
        'ipahealthcheck.ds': [
            'dsbackends = ipahealthcheck.ds.backends',
            'dsconfig = ipahealthcheck.ds.config',
            'dsdiskspace = ipahealthcheck.ds.disk_space',
            'dsdse = ipahealthcheck.ds.dse',
            'dsencryption = ipahealthcheck.ds.encryption',
            'dsfschecks = ipahealthcheck.ds.fs_checks',
            'dsnssssl = ipahealthcheck.ds.nss_ssl',
            'dsplugins = ipahealthcheck.ds.ds_plugins',
            'dsreplication = ipahealthcheck.ds.replication',
            'dsruv = ipahealthcheck.ds.ruv',
        ],
        # plugin modules for ipahealthcheck.system registry
        'ipahealthcheck.system': [
            'filesystemspace = ipahealthcheck.system.filesystemspace',
        ],
        'ipaclustercheck.registry': [
            'ipaclustercheck.ipa = ipaclustercheck.ipa.plugin:registry',
        ],
        'ipaclustercheck.ipa': [
            'crl = ipaclustercheck.ipa.crlmanager',
            'ruv = ipaclustercheck.ipa.ruv',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.6',
)
