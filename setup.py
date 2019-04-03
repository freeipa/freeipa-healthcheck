from setuptools import find_packages, setup


setup(
    name='ipahealthcheck',
    version='0.1',
    namespace_packages=['ipahealthcheck'],
    package_dir={'': 'src'},
    # packages=find_packages(where='src'),
    packages=[
        'ipahealthcheck.core',
        'ipahealthcheck.dogtag',
        'ipahealthcheck.ds',
        'ipahealthcheck.ipa',
        'ipahealthcheck.meta'
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
        ],
        # plugin modules for ipahealthcheck.meta registry
        'ipahealthcheck.meta': [
            'meta = ipahealthcheck.meta.core',
            'services = ipahealthcheck.meta.services',
        ],
        # plugin modules for ipahealthcheck.ipa registry
        'ipahealthcheck.ipa': [
            'ipacerts = ipahealthcheck.ipa.certs',
            'ipafiles = ipahealthcheck.ipa.files',
            'ipahost = ipahealthcheck.ipa.host',
            'ipatopology = ipahealthcheck.ipa.topology',
        ],
        # plugin modules for ipahealthcheck.dogtag registry
        'ipahealthcheck.dogtag': [
            'dogtagca = ipahealthcheck.dogtag.ca',
        ],
        # plugin modules for ipahealthcheck.ds registry
        'ipahealthcheck.ds': [
            'dsreplication = ipahealthcheck.ds.replication',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
)
