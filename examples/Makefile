EXAMPLES=mx \
chaos \
key2ds \
axfr \
fp \
reflect \
q \
funkensturm \


all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

install: all
	for i in $(EXAMPLES); do gomake -C $$i install; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
