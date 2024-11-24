// SIP tools

#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdio.h>

static inline char *sip_skip_space(char *s, char *e)
{
  if (!s)
    return NULL;
  if (!e)
    e = s + strlen(s);
  // maybe wrapped line handling may be better on Rx
  while (s < e && (*s == ' ' || *s == 9 || *s == '\n' || *s == '\r'))
    s++;
  return s;
}

char *sip_skip_display(char *s, char *e)
{                               // skip display string at start
  if (!s)
    return NULL;
  if (!e)
    e = s + strlen(s);
  s = sip_skip_space(s, e);
  if (s < e && *s == '"')
  {
    s++;
    while (s < e && *s != '"')
    {
      if (*s == '\\' && s + 1 < e)
        s++;
      s++;
    }
    if (s < e)
      s++;
  }
  else
  {                             // make be token list
    while (s < e)
    {
      char *p = s;
      while (p < e &&
             (isalpha((int)*(unsigned char*)p) || isdigit((int)*(unsigned char*)p) || *p == '-' || *p == '.' || *p == '!' || *p == '%' || *p == '*' || *p == '_'
              || *p == '+' || *p == '`' || *p == '\'' || *p == '~'))
        p++;
      if (p < e && *p != ' ')
        break;                  // was not a token
      p = sip_skip_space(p, e);
      if (p < e)
        s = p;                  // Skip this token
      else
        break;                  // Leave last part as probably a hostname
    }
  }
  return sip_skip_space(s, e);
}

char *sip_find_display(char *s, char *e, char **end)
{                               // find display name
  if (end)
    *end = NULL;
  if (!s)
    return NULL;
  if (!e)
    e = s + strlen(s);
  s = sip_skip_space(s, e);
  char *q = sip_skip_display(s, e);
  while (q > s && (q[-1] == ' ' || q[-1] == 9 || q[-1] == '\n' || q[-1] == '\r'))
    q--;
  if (q == s)
    return NULL;                // not found
  if (q - s >= 2 && *s == '"' && q[-1] == '"')
  {
    s++;
    q--;
  }
  if (end)
    *end = q;
  return s;
}

int sip_esc_cmp(char *s, char *e, char *c)
{                               // compare escaped s-e with un-escaped null terminated c
  if (!s && !c)
    return 0;
  if (!c)
    return 1;
  if (!s)
    return -1;
  if (!e)
    e = s + strlen(s);
  while (s < e && *c)
  {
    int v = *s;
    if (*s == '%' && s + 3 < e && isxdigit((int)((unsigned char*)s)[1]) && isxdigit((int)((unsigned char*)s)[2]))
    {
      s++;
      v = (*s & 15) + (isalpha((int)*(unsigned char *)s) ? 9 : 0);
      s++;
      v = (v << 4) + (*s & 15) + (isalpha((int)*(unsigned char*)s) ? 9 : 0);
    }
    if (v < *c)
      return -1;
    if (v > *c)
      return 1;
    s++;
    c++;
  }
  if (s < e)
    return -1;
  if (*c)
    return 1;
  return 0;
}

int sip_esc_esc_cmp(char *s, char *e, char *s2, char *e2)
{                               // compare escaped with escaped
  if (!s && !s2)
    return 0;
  if (!s2)
    return 1;
  if (!s)
    return -1;
  if (!e)
    e = s + strlen(s);
  while (s < e && s2 < e2)
  {
    int v = *s;
    if (*s == '%' && s + 3 <= e && isxdigit((int)((unsigned char*)s)[1]) && isxdigit((int)((unsigned char*)s)[2]))
    {
      s++;
      v = (*s & 15) + (isalpha((int)*(unsigned char*)s) ? 9 : 0);
      s++;
      v = (v << 4) + (*s & 15) + (isalpha((int)*(unsigned char*)s) ? 9 : 0);
    }
    int v2 = *s2;
    if (*s2 == '%' && s2 + 3 <= e2 && isxdigit((int)((unsigned char*)s2)[1]) && isxdigit((int)((unsigned char*)s2)[2]))
    {
      s2++;
      v2 = (*s2 & 15) + (isalpha((int)*(unsigned char*)s2) ? 9 : 0);
      s2++;
      v2 = (v2 << 4) + (*s2 & 15) + (isalpha((int)*(unsigned char*)s2) ? 9 : 0);
    }
    if (v < v2)
      return -1;
    if (v2 < v)
      return 1;
    s++;
    s2++;
  }
  if (s < e)
    return -1;
  if (s2 < e2)
    return 1;
  return 0;
}

char *sip_find_request(char *p, char *e, char **end)
{
  if (end)
    *end = NULL;
  if (!p)
    return NULL;
  char *l = p;
  while (l < e && *l >= ' ')
    l++;                        // end of line
  e = l;
  while (p < e && *p != ' ')
    p++;
  while (p < e && *p == ' ')
    p++;
  char *s = p;
  while (p < e && *p > ' ')
    p++;
  if (end)
    *end = p;
  return s;
}

char *sip_find_local(char *s, char *e, char **end)
{                               // extract local part of URI
  if (end)
    *end = NULL;
  if (!s)
    return NULL;
  if (!e)
    e = s + strlen(s);
  if (s + 4 <= e && !strncasecmp(s, "sip:", 4))
    s += 4;
  char *a;
  for (a = s; a < e && *a != '@'; a++) ;
  if (a == e)
    return NULL;                // no local part
  if (end)
    *end = a;
  return s;
}

char *sip_find_uri(char *s, char *e, char **end)
{                               // find URI
  if (end)
    *end = NULL;
  if (!s)
    return NULL;
  if (!e)
    e = s + strlen(s);
  char *p;
  s = sip_skip_display(s, e);
  if (s < e && *s == ',')
    s = sip_skip_space(s + 1, e);
  if (s < e && *s == '<')
  {                             // quoted <...>
    s++;
    p = s;
    while (p < e && *p != '>')
      p++;
  }
  else
  {                             // addr-spec (ambiguous)
    p = s;
    while (p < e && *p != ',')
      p++;
  }
  if (s == p)
    return NULL;
  if (end)
    *end = p;
  return s;
}

char *sip_find_host(char *s, char *e, char **end)
{                               // find Host part
  if (end)
    *end = NULL;
  if (!s)
    return NULL;
  if (!e)
    e = s + strlen(s);
  s = sip_find_uri(s, e, &e);
  if (!s)
    return NULL;
  char *p;
  for (p = s; p < e && isalpha((int)*(unsigned char*)p); p++) ;      // sip: on front
  if (p < e && *p == ':')
    s = p + 1;
  for (p = s; p < e && *p != ';'; p++) ;
  e = p;
  for (p = e; p > s && p[-1] != '@'; p--) ;
  s = p;
  if (s < e && *s == '[')
  {                             // IPv6 literal
    for (p = s; p < e && *p != ']'; p++) ;
    if (p < e && *p == ']')
      p++;
  }
  else
  {                             // Hostname or IPv4 literal
    for (p = s; p < e && (isalpha((int)*(unsigned char*)p) || isdigit((int)*(unsigned char*)p) || *p == '.' || *p == '-'); p++) ;
  }
  e = p;
  if (s == e)
    return NULL;
  if (end)
    *end = e;
  return s;
}

char *sip_find_semi(char *s, char *e, const char *tag, char **end)
{                               // look for specific semicolon separated parameter field
  if (end)
    *end = NULL;
  if (!s)
    return NULL;
  s = sip_skip_display(s, e);
  while (s < e)
  {
    if (*s == '<')
    {
      while (s < e && *s != '>')
        s++;
      if (s < e)
        s++;
      continue;
    }
    if (s < e && *s <= ' ')
    {
      s++;
      continue;
    }
    char *q = s;
    while (s < e && *s > ' ' && *s != '=' && *s != ';' && *s != ',')
      s++;
    if (s > q)
    {
      char *z = s;
      while (z > q && (z[-1] == 9 || z[-1] == ' '))
        z--;
      if (z > q && q + strlen(tag) == z && !strncasecmp(tag, q, z - q))
      {
        if (s == e || *s != '=')
        {
          if (end)
            *end = s;
          return s;
        }
        s++;
        char *q = s;
        while (q < e && *q != ';' && *q != ',')
          q++;
        while (q > s && (q[-1] == 9 || q[-1] == ' '))
          q--;
        if (end)
          *end = q;
        return s;
      }
    }
    while (s < e && *s != ';' && *s != ',')
      s++;
    if (s < e && *s == ',')
      break;
    if (s < e)
      s++;
  }
  return NULL;
}

char *sip_find_comma(char *s, char *e, const char *tag, char **end)
{                               // look for specific comma separated parameter field
  if (end)
    *end = NULL;
  if (!s)
    return NULL;
  if (!e)
    e = s + strlen(s);
  s = sip_skip_display(s, e);
  while (s < e)
  {
    s = sip_skip_space(s, e);
    char *q = s;
    while (s < e && *s > ' ' && *s != '=')
      s++;
    if (s == e || *s != '=')
      continue;
    char *qe = s;
    s++;
    char *v = s, *ve;
    if (s < e && *s == '"')
    {
      s++;
      v = s;
      while (s < e && *s != '"')
      {
        if (s + 1 < e && *s == '\\')
          s++;
        s++;
      }
      ve = s;
      if (s < e)
        s++;
    }
    else
    {
      while (s < e && *s != ',')
        s++;
      while (s > v && s[-1] == ' ')
        s--;
      ve = s;
    }
    if (qe != q && q + strlen(tag) == qe && !strncasecmp(tag, q, qe - q))
    {
      if (end)
        *end = ve;
      return v;
    }
    s = sip_skip_space(s, e);
    if (s < e && *s == ',')
      s++;
  }
  return NULL;
}

char *sip_find_list(char *p, char *e, char **end)
{                               // finds command separated fields within a value of a header
  if (end)
    *end = NULL;
  if (!p)
    return NULL;
  if (!e)
    e = p + strlen(p);
  p = sip_skip_space(p, e);
  while (p < e && *p == ',')
    p = sip_skip_space(p + 1, e);       // skip commas and empt
  if (!p || p == e)
    return NULL;
  char *s = p;
  while (p && p < e && *p != ',')
  {
    if (*p == '"')
      p = sip_skip_display(p, e);
    else if (*p == '<')
      sip_find_uri(p, e, &p);
    else
      p++;
  }
  if (!p)
    return p;
  if (end)
    *end = p;
  return s;
}

char *sip_find_header(char *p, char const * const e, const char *head, const char *alt, char **end, char *prev)
{                               // finds header, after prev returns start of header value, and sets end. Does not include final CRLF
  if (end)
    *end = NULL;
  if (!p)
    return NULL;
  if (prev)
  {
    if (prev < p || prev >= e)
      return NULL;
    p = prev;
  }
  //log(SYS_DEBUG,"Find %s/%s %d",head,alt,e-p);
  while (p < e)
  {
    // end of previous header or initial request/reply line
    while (p < e)
    {
      while (p < e && (*p == 9 || *p >= ' '))
        p++;
      if (p < e && *p == '\r')
        p++;
      if (p < e && *p == '\n')
        p++;
      if (p == e || (*p != ' ' && *p != 9))
        break;
    }
    if (p == e || *p == '\r' || *p == '\n')
      return NULL;              // end of headers?
    // start of line
    char *s = p;
    while (p < e && *p > ' ' && *p != ':')
      p++;
    if (p == s)
      return NULL;              // end of headers or something very strange
    char *q = p;
    while (p < e && (*p == ' ' || *p == 9))
      p++;
    if (s == q || p == e || *p != ':')
      continue;
    if (alt && s + strlen(alt) == q && !strncasecmp(alt, s, q - s))
      break;
    if (head && s + strlen(head) == q && !strncasecmp(head, s, q - s))
      break;
  }
  if (p == e)
    return NULL;                // not found
  p++;
  while (p < e && (*p == 9 || *p == ' '))       // LWS allowed here... so could fold? TODO remove folding in rx?
    p++;
  char *s = p;
  while (p < e)
  {
    while (p < e && (*p == 9 || *p >= ' '))
      p++;
    if (p < e && *p == '\r')
      p++;
    if (p < e && *p == '\n')
      p++;
    if (p == e || (*p != ' ' && *p != 9))
      break;
  }
  if (p > s && p[-1] == '\n')
    p--;
  if (p > s && p[-1] == '\r')
    p--;
  if (end)
    *end = p;
  return s;
}

char *sip_add_header(char **pp, char *e, const char *head, const char *start, const char *end)
{                               // add a header
  if (!start)
    return NULL;
  char *p = *pp;
  if (start && !end)
    end = start + strlen(start);
  if (p + strlen(head) + 2 + (end - start) + 2 + 2 > e)
    return NULL;                // could not add header
  p += sprintf(p, "%s: %.*s\r\n", head, (int)(end - start), start);
  e = *pp;
  *pp = p;
  return e;
}

char *sip_add_header_angle(char **pp, char *e, const char *head, const char *start, const char *end)
{                               // add a header
  if (!start)
    return NULL;
  char *p = *pp;
  if (start && !end)
    end = start + strlen(start);
  if (p + strlen(head) + 2 + (end - start) + 2 + 2 + 2 > e)
    return NULL;                // could not add header
  p += sprintf(p, "%s: <%.*s>\r\n", head, (int)(end - start), start);
  e = *pp;
  *pp = p;
  return e;
}


char *sip_add_extra(char **pp, char *e, const char *tag, const char *start, const char *end, char comma, char quote,
                   char wrap)
{                               // append value to existing header (quoted)
  if (start && !end)
    end = start + strlen(start);
  char *p = *pp;
  if (p[-1] == '\n')
    p--;
  if (p[-1] == '\r')
    p--;
  if (p + strlen(tag ? : "") + 2 + (end - start) + 2 + 2 + (quote ? 2 : 0) > e)
    return NULL;                // could not add header
  if (comma && p[-1] != ' ' && p[-1] != ':')
  {
    *p++ = comma;
    if (comma == ',' && wrap)
    {                           // should we line break
      int n = (end - start) + strlen(tag ? : "") + 1;
      char *q = p;
      while (q[-1] >= ' ' && n < 120)
      {
        q--;
        n++;
      }
      if (n >= 120)
      {
        *p++ = '\r';
        *p++ = '\n';
        *p++ = '\t';
      }
    }
  }
  if (tag)
    p += sprintf(p, "%s", tag);
  if (tag && start)
    *p++ = '=';
  if (quote)
    *p++ = quote;
  if (end > start)
  {
    memcpy(p, start, end - start);
    p += (end - start);
  }
  if (quote)
    *p++ = quote;
  *p++ = '\r';
  *p++ = '\n';
  *p = 0;
  e = (*pp) - 1;
  (*pp) = p;
  return e;
}

unsigned int sip_deescape(char *t, char *et, char *f, char *ef)
{                               // SIP specific URI decode - not like normal URI decode, returns length of response
  if (!f)
  {
    if (t < et)
      *t = 0;
    return 0;
  }
  char *start = t;
  if (f && !ef)
    ef = f + strlen(f);
  while (f < ef && t + 1 < et)
  {
    if (f + 2 < ef && *f == '%')
    {
      f++;
      int v = (*f & 0xF) + (isalpha((int)*(unsigned char*)f) ? 9 : 0);
      f++;
      v = (v << 4) + (*f & 0xF) + (isalpha((int)*(unsigned char*)f) ? 9 : 0);
      *t++ = v;
    }
    else
      *t++ = *f;
    f++;
  }
  *t = 0;
  return t - start;
}
