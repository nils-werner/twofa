import setuptools

setuptools.setup(
    name='twofa',
    version='0.2.0',
    description='A simple command-line 2-factor authentication token manager',
    author='Nils Werner',
    long_description='',
    url='https://github.com/nils-werner/twofa',
    entry_points={'console_scripts': ['2fa = twofa.__init__:cli']},
    install_requires=[
        'pyqrcode',
        'pyotp',
        'click',
        'pyyaml',
        'cryptography',
    ],
    packages=setuptools.find_packages(),
    classifiers=[
        'Environment :: Console',
        'Topic :: Utilities',
    ]
)
