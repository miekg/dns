EXAMPLES=mx \
q \
chaos \
axfr \
reflect \
funkensturm \

all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
