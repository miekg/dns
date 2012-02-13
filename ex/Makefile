.PHONY: ex
EXAMPLES=mx \
	 chaos \
	 key2ds \
	 axfr \
	 fp \
	 reflect \
	 q \

ex:
	for i in $(EXAMPLES); do echo $$i; (cd $$i && go build); done
