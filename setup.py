from setuptools import setup

setup(
    name='invoiceprotector',
    version='1.0',
    description='A tool used to sign text with digital signatures',
    author='@rubeste',
    packages=['invoiceprotector'],
    package_dir={'invoiceprotector': 'src'},
    install_requires=[],
    entry_points={
        'console_scripts': [
            'invo-protec=invoiceprotector.InvoiceProtector:main'
        ]
    }
)