from setuptools import setup
import py2exe

setup(
      options = {'py2exe': {
                            'optimize':2, 
                            'bundle_files': 3, 
                            'compressed': True,
                           }
                },
      console=['tun.py'],
      zipfile = None,
      install_requires=[
          'pywin32',
          'wmi',
          'pycryptodome',
          'dpkt'
      ]
)
