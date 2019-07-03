FROM python:3.7.3-slim-stretch

RUN pip3 install pybind11==2.3.0 python-magic==0.4.15 prompt_toolkit==2.0.9 \
		https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip \
		https://github.com/JonathanSalwan/ROPgadget/archive/v5.8.zip \
		https://github.com/programa-stic/barf-project/archive/4a003e72f1dbee2723b9ece8b482473531145e8e.zip \
	&& apt-get update && apt-get install -y --no-install-recommends \
#		g++ \
		libmagic1 \
	&& rm -rf /var/lib/apt/lists/* /root/.cache

COPY ropgenerator ropgenerator/ropgenerator
COPY scripts ropgenerator/scripts
COPY setup.py ropgenerator/
# At the expense of a larger image size recompilation of ropgenerator can be
# performed without reinstalling g++ (and thus without an active internet
# connection) by uncommenting the previous g++ installation and removing the
# apt-get commands of the following RUN
RUN apt-get update && apt-get install -y --no-install-recommends g++ \
	&& cd ropgenerator && python3 setup.py install \
	&& cd .. && rm -rf ropgenerator \
	&& apt-get -y remove g++ \
	&& apt-get purge -y --autoremove \
	&& rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["ROPGenerator"]
