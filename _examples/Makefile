EXAMPLES=mx \
chaos \
key2ds \
axfr \
reflect \
q \
qperf \
funkensturm \


all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
