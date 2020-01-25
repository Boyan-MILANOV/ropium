FROM python:3.7.3-slim-stretch

RUN pip3 install prompt_toolkit==2.0.9 \
#		https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip \
		capstone \
        https://github.com/JonathanSalwan/ROPgadget/archive/v5.9.zip \
	&& apt-get update && apt-get install -y --no-install-recommends \
#		g++ \
		libmagic1 \
        make \
        libcapstone-dev \
	&& rm -rf /var/lib/apt/lists/* /root/.cache

COPY . ropium/
# At the expense of a larger image size, recompilation of ropium can be
# performed without reinstalling g++ (and thus without an active internet
# connection) by uncommenting the previous g++ installation and removing the
# apt-get commands of the following RUN
RUN apt-get update && apt-get install -y --no-install-recommends g++ \
	&& cd ropium && make && make test && make install \
	&& cd .. && rm -rf ropium \
	&& apt-get -y remove g++ \
	&& apt-get purge -y --autoremove \
	&& rm -rf /var/lib/apt/lists/*

# ENTRYPOINT ["ropium"]
