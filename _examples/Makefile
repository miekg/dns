EXAMPLES=mx \
q \
chaos \
axfr \
reflect \
xfrprx \
key2ds \

# funkensturm  -- need fix

all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
