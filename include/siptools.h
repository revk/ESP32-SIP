// SIP tools

// Setting any start but not end will assume end is end of NULL terminated string from start

// Move passed a display (i.e "...")
const char *sip_skip_display(const char *s, const char *e);

// Find functions take start (s) and end (e) and look for a thing in that range
// They return NULL if not found, or the start of what was found, and store end of what was found in end (if not NULL)
const char *sip_find_display(const char *s, const char *e, const char **end);
const char *sip_find_request(const char *p, const char *e, const char **end);
const char *sip_find_local(const char *s, const char *e, const char **end);
const char *sip_find_uri(const char *s, const char *e, const char **end);
const char *sip_find_host(const char *s, const char *e, const char **end);
const char *sip_find_semi(const char *s, const char *e, const char *tag, const char **end);
const char *sip_find_comma(const char *s, const char *e, const char *tag, const char **end);
const char *sip_find_list(const char *p, const char *e, const char **end);
const char *sip_find_header(const char *p, const char * e, const char *head, const char *alt, const char **end, const char *prev);

// Add functions add to end of a buffer at *pp not going beyond e, the move *pp on
// In some cases it is assumed *pp has /r/n before it, which can be stripped back
const char *sip_add_texte(char ** const pp, const char *e, const char *text,const char *texte);
#define	sip_add_text(p,e,t)	sip_add_texte(p,e,t,NULL)

const char *sip_add_esc(char ** const pp, const char *e, const char *text,const char *texte);
#define	sip_add_esc(p,e,t)	sip_add_esce(p,e,t,NULL)

const char *sip_add_header(char ** const pp, const char *e, const char *head, const char *start, const char *end);
const char *sip_add_header_angle(char ** const pp, const char *e, const char *head, const char *local,const char *locale,const char *domain,const char *domaine);

const char *sip_add_extra(char ** const pp, const char *e, const char *tag, const char *start, const char *end, char comma, char quote, char wrap);

// Simple de-escaping from and to
unsigned int sip_deescape(char *t, char *et, const char *f, const char *ef);

// Escaped comparisons
int sip_esc_cmp(const char *s, const char *e, const char *c);
int sip_esc_esc_cmp(const char *s, const char *e, const char *s2, const char *e2);
