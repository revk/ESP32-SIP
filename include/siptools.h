// SIP tools

// Setting any start but not end will assume end is end of NULL terminated string from start

typedef	char *string_t;
typedef	const char *cstring_t;

// Move passed a display (i.e "...")
cstring_t sip_skip_display(cstring_t s, cstring_t e);

// Find functions take start (s) and end (e) and look for a thing in that range
// They return NULL if not found, or the start of what was found, and store end of what was found in end (if not NULL)
cstring_t sip_find_display(cstring_t s, cstring_t e, cstring_t *end);
cstring_t sip_find_request(cstring_t s, cstring_t e, cstring_t *end);
cstring_t sip_find_local(cstring_t s, cstring_t e, cstring_t *end);
cstring_t sip_find_uri(cstring_t s, cstring_t e, cstring_t *end);
cstring_t sip_find_host(cstring_t s, cstring_t e, cstring_t *end);
cstring_t sip_find_semi(cstring_t s, cstring_t e, cstring_t tag, cstring_t *end);
cstring_t sip_find_comma(cstring_t s, cstring_t e, cstring_t tag, cstring_t *end);
cstring_t sip_find_list(cstring_t s, cstring_t e, cstring_t *end);
cstring_t sip_find_header(cstring_t s, cstring_t  e, cstring_t head, cstring_t alt, cstring_t *end, cstring_t prev);

// Add functions add to end of a buffer at *pp not going beyond e, the move *pp on
// In some cases it is assumed *pp has /r/n before it, which can be stripped back
cstring_t sip_add_texte(string_t* pp, cstring_t e, cstring_t text,cstring_t texte);
#define	sip_add_text(p,e,t)	sip_add_texte(p,e,t,NULL)

cstring_t sip_add_esce(string_t* pp, cstring_t e, cstring_t text,cstring_t texte);
#define	sip_add_esc(p,e,t)	sip_add_esce(p,e,t,NULL)

cstring_t sip_add_headere(string_t* pp, cstring_t e, cstring_t head, cstring_t start, cstring_t end);
#define	sip_add_header(p,e,h,s) sip_add_headere(p,e,h,s,NULL)
cstring_t sip_add_headerf(string_t* pp, cstring_t e, cstring_t head, cstring_t fmt,...);
cstring_t sip_add_header_angle(string_t* pp, cstring_t e, cstring_t head, cstring_t local,cstring_t locale,cstring_t domain,cstring_t domaine);

cstring_t sip_add_extra(string_t* pp, cstring_t e, cstring_t tag, cstring_t start, cstring_t end, char comma, char quote, char wrap);
#define sip_add_comma(pp,E,t,s,e) sip_add_extra(pp,E,t,s,e,',',0,0)
#define sip_add_comma_quote(pp,E,t,s,e) sip_add_extra(pp,E,t,s,e,',','"',0)
#define sip_add_semi(pp,E,t,s,e) sip_add_extra(pp,E,t,s,e,';',0,0)
#define sip_add_semi_quote(pp,E,t,s,e) sip_add_extra(pp,E,t,s,e,';','"',0)

cstring_t sip_add_eol(string_t* pp, cstring_t e);

// Simple de-escaping from and to
unsigned int sip_deescape(string_t t,cstring_t et, cstring_t f, cstring_t ef);

// Escaped comparisons
int sip_esc_cmp(cstring_t s, cstring_t e, cstring_t c);
int sip_esc_esc_cmp(cstring_t s, cstring_t e, cstring_t s2, cstring_t e2);

