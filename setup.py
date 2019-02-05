from setuptools import find_packages, setup


setup(
    name='idmcheck',
    namespace_packages=['idmcheck'],
    package_dir={'': 'src'},
    # packages=find_packages(where='src'),
    packages=[
        'idmcheck.core',
        'idmcheck.ipa'
    ],
    entry_points={
        # creates bin/idmcheck
        'console_scripts': [
            'idmcheck = idmcheck.core.main:main',
        ],
        # subsystem registries
        'idmcheck.registry': [
            'idmcheck.ipa = idmcheck.ipa.plugin:registry',
            'idmcheck.dogtag = idmcheck.dogtag.plugin:registry',
        ],
        # plugin modules for idmcheck.ipa registry
        'idmcheck.ipa': [
            'ipacerts = idmcheck.ipa.certs',
            'ipakerberos = idmcheck.ipa.kerberos',
        ],
        # plugin modules for idmcheck.ipa registry
        'idmcheck.dogtag': [
            'example = idmcheck.dogtag.example',
        ],
    },
    install_requires=['ipaclient'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
)
