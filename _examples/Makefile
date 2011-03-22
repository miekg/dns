EXAMPLES=mx \
q \
chaos \
axfr \
reflect \
funkensturm \
xfrprx \
ds2key \

all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
