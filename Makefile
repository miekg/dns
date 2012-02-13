.PHONY: ex clean

EXAMPLES=mx \
	 chaos \
	 key2ds \
	 axfr \
	 fp \
	 reflect \
	 q \

ex:
	for i in $(EXAMPLES); do go build dns/ex/$$i; done

clean:
	rm -f $(EXAMPLES)
