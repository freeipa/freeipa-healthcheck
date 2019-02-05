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
        'console_scripts': [
            'idmcheck = idmcheck.core.main:main',
        ],
        'idmcheck.ipa': [
            'ipacerts = idmcheck.ipa.certs:register',
            'ipakerberos = idmcheck.ipa.kerberos:register',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
)
