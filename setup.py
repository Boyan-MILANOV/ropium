from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

import os
import pwd
import grp
import sys

ROPGenerator_dir = os.path.expanduser('~')+"/.ROPGenerator/"

class get_pybind_include(object):
    """Helper class to determine the pybind11 include path
    The purpose of this class is to postpone importing pybind11
    until it is actually installed, so that the ``get_include()``
    method can be invoked. """

    def __init__(self, user=False):
        self.user = user

    def __str__(self):
        import pybind11
        return pybind11.get_include(self.user)


def has_flag(compiler, flagname):
    """Return a boolean indicating whether a flag name is supported on
    the specified compiler.
    """
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.cpp') as f:
        f.write('int main (int argc, char **argv) { return 0; }')
        try:
            compiler.compile([f.name], extra_postargs=[flagname])
        except setuptools.distutils.errors.CompileError:
            return False
    return True


def cpp_flag(compiler):
    """Return the -std=c++[11/14] compiler flag.
    The c++14 is prefered over c++11 (when it is available).
    """
    if has_flag(compiler, '-std=c++11'):
        return '-std=c++11'
    else:
        raise RuntimeError('Unsupported compiler -- at least C++11 support '
                           'is needed!')

def get_cpp_files():
    """ Return the list of C files to compile 
    """ 
    core_dir = os.path.dirname(os.path.abspath(__file__))+'/ropgenerator/cpp-core/'
    res = [core_dir+f for f in os.listdir(core_dir) if f.endswith(".cpp")]
    return res

class BuildExt(build_ext):
    """A custom build extension for adding compiler-specific options."""
    c_opts = {
        'msvc': ['/EHsc'],
        'unix': [],
    }

    if sys.platform == 'darwin':
        c_opts['unix'] += ['-stdlib=libc++', '-mmacosx-version-min=10.7']

    def build_extensions(self):
        ct = self.compiler.compiler_type
        opts = self.c_opts.get(ct, [])
        if ct == 'unix':
            opts.append('-DVERSION_INFO="%s"' % self.distribution.get_version())
            opts.append(cpp_flag(self.compiler))
            if has_flag(self.compiler, '-fvisibility=hidden'):
                opts.append('-fvisibility=hidden')
            opts.append('-Wno-delete-non-virtual-dtor')
            opts.append('-Wno-return-type')
            opts.append("-g0") # Maximum optimisation DEBUG
            opts.append("-O2") # Fast compile DEBUG
        elif ct == 'msvc':
            opts.append('/DVERSION_INFO=\\"%s\\"' % self.distribution.get_version())
        for ext in self.extensions:
            ext.extra_compile_args = opts
        build_ext.build_extensions(self)


#os.environ["CC"]="g++"
os.environ["CC"]="clang"

setup(  name='ropgenerator',
        version = "2.0",
        description = "ROPGenerator makes ROP exploits easy by finding and\
                        chaining gadgets for you",
        url="https://github.com/Boyan-MILANOV/ropgenerator",
        author="Boyan MILANOV",
        author_email="boyan.milanov@hotmail.fr",
        license="MIT",
        classifiers=[
        'Development Status :: 4 - Beta',
        "Environment :: Console",
        "Topic :: Security",
        ],    
        packages=['ropgenerator', 'ropgenerator.main', 'ropgenerator.core', 'ropgenerator.semantic', 'ropgenerator.exploit', 'ropgenerator.exploit.syscall'],
        scripts=['ROPGenerator', 'ROPGenerator.py'],
        keywords='rop generator chain gadget semantic automated exploit ropchain',
        zip_safe = False,
        data_files=[(ROPGenerator_dir, [])], 
        install_requires=['prompt_toolkit>=2.0', 'python-magic', 'barf==0.5.0', 'lief'],
        # Cpp compilation 
        ext_modules=[
            Extension(
                'ropgenerator_core_',
                get_cpp_files(),
                include_dirs=[
                    # Path to pybind11 headers
                    str(get_pybind_include()),
                    str(get_pybind_include(user=True)),
                    "ropgenerator/cpp-core/include/"
                ],
                language='c++'
            ),
        ],
        cmdclass={'build_ext': BuildExt}
    )

