FROM python:3.7.3-stretch

# http://bugs.python.org/issue19846
# > At the moment, setting "LANG=C" on a Linux system *fundamentally breaks Python 3*, and that's not OK.
ENV LANG C.UTF-8
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE DontWarn

RUN set -ex \
	&& apt-get update \
	&& apt-get install -y \
		software-properties-common \
		make \
		gcc \
		g++ \
		git \
		libc-dev \
	&& add-apt-repository "deb http://apt.llvm.org/stretch/ llvm-toolchain-stretch main" \
	&& wget https://apt.llvm.org/llvm-snapshot.gpg.key \
	&& apt-key add llvm-snapshot.gpg.key \
	&& apt-get update \
	&& apt-get -y install clang-9 lldb-9 lld-9 \
	&& ln -s $(which clang-9) /usr/bin/clang \
	&& pip3 install pytest \
	&& pip3 install pybind11 \
	&& pip3 install python-magic \
	&& pip3 install prompt_toolkit \
	&& pip3 install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip \
	&& git clone https://github.com/programa-stic/barf-project && cd barf-project \
	&& python3 setup.py install \
	&& cd / \
	&& git clone https://github.com/JonathanSalwan/ROPgadget \
	&& cd ROPgadget && python3 setup.py install \
	&& cd / \
	&& git clone https://github.com/Boyan-MILANOV/ropgenerator \
	&& cd ropgenerator && python3 setup.py install \
	&& rm -rf /usr/bin/clang \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# 	&& apt-get -y remove --purge make gcc g++ git libc-dev clang-9 lldb-9 lld-9 mysql-common '^libmagic*' '^llvm*' '^libgdk*' '^x11-*' '^libx11-*' \
