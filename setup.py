from distutils.core import setup

classifiers = [
    'Development Status :: 3 - Alpha',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Topic :: Security :: Cryptography',
]

setup(
    name="tinytls",
    version="%d.%d.%d" % __import__('tinytls').VERSION,
    url='https://github.com/nakagami/tinytls/',
    classifiers=classifiers,
    keywords=['TLS'],
    author='Hajime Nakagami',
    author_email='nakagami@gmail.com',
    description='TLS1.3 protocol wrapper',
    long_description=open('README.rst').read(),
    license="MIT",
    packages=['tinytls'],
)
