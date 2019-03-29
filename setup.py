from setuptools import find_packages, setup


setup(
    name='ipahealthcheck',
    namespace_packages=['ipahealthcheck'],
    package_dir={'': 'src'},
    # packages=find_packages(where='src'),
    packages=[
        'ipahealthcheck.core',
        'ipahealthcheck.dogtag',
        'ipahealthcheck.ipa'
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
        ],
        # plugin modules for ipahealthcheck.dogtag registry
        'ipahealthcheck.dogtag': [
            'dogtagca = ipahealthcheck.dogtag.ca',
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
)
