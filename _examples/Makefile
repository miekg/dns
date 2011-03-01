EXAMPLES=mx \
q \
chaos \
axfr \
reflect \
funkensturm \
ns \

all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
