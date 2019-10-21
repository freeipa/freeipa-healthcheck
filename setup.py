from setuptools import find_packages, setup


setup(
    name='ipahealthcheck',
    version='0.3',
    namespace_packages=['ipahealthcheck'],
    package_dir={'': 'src'},
    # packages=find_packages(where='src'),
    packages=[
        'ipahealthcheck.core',
        'ipahealthcheck.dogtag',
        'ipahealthcheck.ds',
        'ipahealthcheck.ipa',
        'ipahealthcheck.meta',
        'ipahealthcheck.system'
    ],
    entry_points={
        # creates bin/ipahealthcheck
        'console_scripts': [
            'ipa-healthcheck = ipahealthcheck.core.main:main',
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
            'ipadna = ipahealthcheck.ipa.dna',
            'ipadns = ipahealthcheck.ipa.idns',
            'ipafiles = ipahealthcheck.ipa.files',
            'ipahost = ipahealthcheck.ipa.host',
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
            'dsreplication = ipahealthcheck.ds.replication',
            'dsruv = ipahealthcheck.ds.ruv',
        ],
        # plugin modules for ipahealthcheck.system registry
        'ipahealthcheck.system': [
            'filesystemspace = ipahealthcheck.system.filesystemspace',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
    setup_requires=['pytest-runner',],
    tests_require=['pytest',],
)
