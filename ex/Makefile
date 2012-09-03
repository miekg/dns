.PHONY: ex
EXAMPLES=chaos \
	 axfr \
	 reflect \
	 q \

ex:
	for i in $(EXAMPLES); do echo $$i; (cd $$i && go install); done
