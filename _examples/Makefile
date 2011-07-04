EXAMPLES=mx \
chaos \
key2ds \
axfr \
q
# these need to be fixed
#reflect \
#xfrprx \
#funkensturm

all: 
	for i in $(EXAMPLES); do gomake -C $$i; done

clean:
	for i in $(EXAMPLES); do gomake -C $$i clean; done
