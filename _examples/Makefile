EXAMPLES=mx \
chaos \
key2ds \
axfr
# these need to be fixed
#q \
#reflect \
#xfrprx \
#funkensturm

all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
