all: 
	gomake -C mx		# query for MX records
	gomake -C q		# Dig-like tool
	gomake -C chaos		# show version.bind and hostname.bind
	gomake -C axfr		# perform an AXFR
	gomake -C notify	# send a notify msg
	gomake -C reflect	# a reflector nameserver
	gomake -C rude		# a rude nameserver (send formerr back)
	goamke -C s		# a complete nameserver

clean:
	gomake -C mx clean
	gomake -C q clean
	gomake -C chaos clean
	gomake -C axfr clean
	gomake -C notify clean
	gomake -C reflect clean
	gomake -C rude clean
	goamke -C s
