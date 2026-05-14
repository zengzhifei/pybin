from setuptools import setup, find_packages

from pybin import __about__

with open("README.md") as f:
    long_description = f.read()

setup(
    name=__about__.__name__,
    version=__about__.__version__,
    description=__about__.__doc__,
    long_description=long_description,
    long_description_content_type="text/markdown",
    author=__about__.__author__,
    author_email=__about__.__author_email__,
    url=__about__.__url__,
    packages=find_packages(),
    python_requires='>=3.6',
    license='MIT',
)
