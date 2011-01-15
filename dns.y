
%{ 

package dns

// A yacc parser for DNS Resource Records contained in strings

%}

%union {
    string  string
    rrtype  uint16
    class   uint16
    ttl     uint16

}

/*
 * Types known to package dns
 */
%token <rrtype> RR_A RR_NS RR_MX RR_CNAME RR_AAAA RR_DNSKEY RR_RRSIG RR_DS

/*
 * Other elements of the Resource Records
 */
%token <ttl>    TTL
%token <class>  CLASS
%token <string> STR
%%
rr:     name TTL CLASS 
  {
  
  };

name:   label
    |   name '.' label

label:  STR
%%

type DnsLex int
