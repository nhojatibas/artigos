from setuptools import setup, find_packages


def read(filename):
    return [
        req.strip()
        for req
        in open(filename).readlines()
        ]


setup(
    name="articles",
    version="0.0.1",
    description="Controle de artigos",
    packages=find_packages(),
    include_package_data=True,
    install_requires=read("requirements.txt")
    )
