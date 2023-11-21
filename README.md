autor: ADAM GABRYS  
login: xgabry01  
datum: 5.11.2023  

popis: Implementace programu do předmětu ISA, kdy bylo za úkol naimplementovat jednoduchý neblokující paralelní LDAP server řešící vyhledávání v lokální databázi.  

příklad spuštění: ./isa-ldapserver {-p <port>} -f <soubor>  

Omezení: Neimplementovány filtry AND, OR, NOT  

Specifikace: Ze zadání jsem pochopil, že máme posílat vždy atributy cn, mail. Tedy atribut uid neposílám, pouze je nastaven u dn.  

seznam odevzdaných souborů:  
README.md  
tests  
     - /cn_basic.txt  
     - /ipv6_loopback_interface.txt  
     - /loopback_interface.txt  
     - /mail_equalityMatch.txt  
     - /mail_multiple_substring.txt  
     - /mail_multiple_substring.txt  
     - /mail_substring.txt  
     - /no_base.txt  
     - /size_limit_exceeded.txt  
     - /uid_multiple_substring.txt  
     - /uid_simple_equalityMatch.txt  
manual.pdf  
handle_search_request.cpp  
handle_search_res_done.cpp  
handle_search_res_entry.cpp  
isa-ldapserver-main.cpp  
ldap_filters.cpp  
ldap_functions.cpp  
ldap_functions.hpp  
proccessing_help_functions.cpp  
server.cpp  
server.hpp  
Makefile  
