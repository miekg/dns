.PHONY: examples

EXAMPLES=mx \
	 chaos \
	 key2ds \
	 axfr \
	 fp \
	 reflect \
	 q \
	 funkensturm \

examples:
	for i in $(EXAMPLES); do go build dns/examples/$$i; done
