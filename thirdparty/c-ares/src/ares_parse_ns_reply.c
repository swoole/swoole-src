/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

/*
 * ares_parse_ns_reply created by Vlad Dinulescu <vlad.dinulescu@avira.com>
 *      on behalf of AVIRA Gmbh - http://www.avira.com
 */

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

int ares_parse_ns_reply( const unsigned char* abuf, int alen,
                         struct hostent** host )
{
  unsigned int qdcount, ancount;
  int status, i, rr_type, rr_class, rr_len;
  int nameservers_num;
  long len;
  const unsigned char *aptr;
  char* hostname, *rr_name, *rr_data, **nameservers;
  struct hostent *hostent;

  /* Set *host to NULL for all failure cases. */
  *host = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if ( alen < HFIXEDSZ )
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT( abuf );
  ancount = DNS_HEADER_ANCOUNT( abuf );
  if ( qdcount != 1 )
    return ARES_EBADRESP;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares__expand_name_for_response( aptr, abuf, alen, &hostname, &len);
  if ( status != ARES_SUCCESS )
    return status;
  if ( aptr + len + QFIXEDSZ > abuf + alen )
  {
    ares_free( hostname );
    return ARES_EBADRESP;
  }
  aptr += len + QFIXEDSZ;

  /* Allocate nameservers array; ancount gives an upper bound */
  nameservers = ares_malloc( ( ancount + 1 ) * sizeof( char * ) );
  if ( !nameservers )
  {
    ares_free( hostname );
    return ARES_ENOMEM;
  }
  nameservers_num = 0;

  /* Examine each answer resource record (RR) in turn. */
  for ( i = 0; i < ( int ) ancount; i++ )
  {
    /* Decode the RR up to the data field. */
    status = ares__expand_name_for_response( aptr, abuf, alen, &rr_name, &len );
    if ( status != ARES_SUCCESS )
      break;
    aptr += len;
    if ( aptr + RRFIXEDSZ > abuf + alen )
    {
      status = ARES_EBADRESP;
      ares_free(rr_name);
      break;
    }
    rr_type = DNS_RR_TYPE( aptr );
    rr_class = DNS_RR_CLASS( aptr );
    rr_len = DNS_RR_LEN( aptr );
    aptr += RRFIXEDSZ;
    if (aptr + rr_len > abuf + alen)
      {
        ares_free(rr_name);
        status = ARES_EBADRESP;
        break;
      }

    if ( rr_class == C_IN && rr_type == T_NS )
    {
      /* Decode the RR data and add it to the nameservers list */
      status = ares__expand_name_for_response( aptr, abuf, alen, &rr_data,
                                               &len);
      if ( status != ARES_SUCCESS )
      {
        ares_free(rr_name);
        break;
      }

      nameservers[nameservers_num] = ares_malloc(strlen(rr_data)+1);

      if (nameservers[nameservers_num]==NULL)
      {
        ares_free(rr_name);
        ares_free(rr_data);
        status=ARES_ENOMEM;
        break;
      }
      strcpy(nameservers[nameservers_num],rr_data);
      ares_free(rr_data);

      nameservers_num++;
    }

    ares_free( rr_name );

    aptr += rr_len;
    if ( aptr > abuf + alen )
    {  /* LCOV_EXCL_START: already checked above */
      status = ARES_EBADRESP;
      break;
    }  /* LCOV_EXCL_STOP */
  }

  if ( status == ARES_SUCCESS && nameservers_num == 0 )
  {
    status = ARES_ENODATA;
  }
  if ( status == ARES_SUCCESS )
  {
    /* We got our answer.  Allocate memory to build the host entry. */
    nameservers[nameservers_num] = NULL;
    hostent = ares_malloc( sizeof( struct hostent ) );
    if ( hostent )
    {
      hostent->h_addr_list = ares_malloc( 1 * sizeof( char * ) );
      if ( hostent->h_addr_list )
      {
        /* Fill in the hostent and return successfully. */
        hostent->h_name = hostname;
        hostent->h_aliases = nameservers;
        hostent->h_addrtype = AF_INET;
        hostent->h_length = sizeof( struct in_addr );
        hostent->h_addr_list[0] = NULL;
        *host = hostent;
        return ARES_SUCCESS;
      }
      ares_free( hostent );
    }
    status = ARES_ENOMEM;
  }
  for ( i = 0; i < nameservers_num; i++ )
    ares_free( nameservers[i] );
  ares_free( nameservers );
  ares_free( hostname );
  return status;
}
