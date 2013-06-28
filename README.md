dnsRedir
========
A small command-line DNS server written in Python.

- Tim Newsham < tim at isecpartners dot com >
- 27 Jun 2013


Overview
=======
dnsRedir.py is a small DNS server that will respond to certain
queries with addresses provided on the command line. All other
queries will be proxied to a "real" name server. This program
can be used to redirect a few domain names to test addresses for 
the purpose of security and protocol testing.

See man.txt for more details.

Similar programs:
* dnschef: https://thesprawl.org/projects/dnschef/


QUICKSTART
=======
- Run the server
  - $ ./dnsRedir.py -p 1053 'A:www\.evil\.com\.:1.2.3.4'

- Now query it
  - $ dig -p 1053 www.evil.com @localhost
  - $ dig -p 1053 www.google.com @localhost
    


DEPENDENCIES
=======
dnsRedir.py requires Python 2.5 or greater. It does not require
any other dependencies and can be run from a single source file.


