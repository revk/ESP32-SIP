// SIP tools


char *sip_skip_display(char *s, char *e);
char *sip_find_display(char *s, char *e, char **end);
int sip_esc_cmp(char *s, char *e, char *c);
int sip_esc_esc_cmp(char *s, char *e, char *s2, char *e2);
char *sip_find_request(char *p, char *e, char **end);
char *sip_find_local(char *s, char *e, char **end);
char *sip_find_uri(char *s, char *e, char **end);
char *sip_find_host(char *s, char *e, char **end);
char *sip_find_semi(char *s, char *e, const char *tag, char **end);
char *sip_find_comma(char *s, char *e, const char *tag, char **end);
char *sip_find_list(char *p, char *e, char **end);
char *sip_find_header(char *p, char const * const e, const char *head, const char *alt, char **end, char *prev);
char *sip_add_header(char **pp, char *e, const char *head, const char *start, const char *end);
char *sip_add_header_angle(char **pp, char *e, const char *head, const char *start, const char *end);
char *sip_add_extra(char **pp, char *e, const char *tag, const char *start, const char *end, char comma, char quote, char wrap);
unsigned int sip_deescape(char *t, char *et, char *f, char *ef);
