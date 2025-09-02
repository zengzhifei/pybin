from setuptools import setup

import __about__

setup(
    name=__about__.__name__,
    version=__about__.__version__,
    description=__about__.__doc__,
    long_description=open("README.md").read(),
    author=__about__.__author__,
    author_email=__about__.__author_email__,
    url=__about__.__url__,
    package_dir={'pybin': ''},
    py_modules=['pybin.sdk', 'pybin.ann', 'pybin.__about__'],
    platforms='any',
    python_requires='>=3.6',
    license='MIT',
)
