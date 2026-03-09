from setuptools import setup, find_packages

setup(
    name="api_server",
    version="0.1.0",
    description="User and IoT Resource management API.",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        line.strip()
        for line in open("requirements.txt").readlines()
        if line and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "start-api-server=API_server.app.main:run",
        ],
    },
)