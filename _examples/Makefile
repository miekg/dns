EXAMPLES=mx \
q \
chaos \
axfr \
reflect \
funkensturm \
xfrprx \
key2ds \

all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
