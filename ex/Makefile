.PHONY: ex
EXAMPLES=chaos \
	 key2ds \
	 axfr \
	 reflect \
	 q \

ex:
	for i in $(EXAMPLES); do echo $$i; (cd $$i && go install); done
