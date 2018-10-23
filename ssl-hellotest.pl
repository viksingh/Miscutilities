#!/usr/bin/perl
#
$min_proto_version    = 0;   ## SSLv3=0, TLSv1.2=3
$try_with_tlsext_sni  = 0;   ## try with TLS extension servername_indication
$try_with_tlsext_sig  = 0;   ## try with TLS extension signature_algorithms

while ( substr($ARGV[0],0,1) eq "-" ) {
    if ( $ARGV[0] =~ m/^-[0-3]$/ ) {
       $min_proto_version = substr($ARGV[0],1,1);
       shift(@ARGV);
       next;
    }
    if ( $ARGV[0] eq "-sni" ) {
       $try_with_tlsext_sni = 1;
       shift(@ARGV);
       next;
    }
    if ( $ARGV[0] eq "-sig" ) {
       $try_with_tlsext_sig = 1;
       shift(@ARGV);
       next;
    }
    last;
}


if ( $#ARGV<1 || substr($ARGV[0],0,1) eq "-" ) {
    die("Usage: ssl-hellotest [-0|-1|-2|-3] [-sni] <srvhost> <tcp-portno>\n\n"
        . "   -0/-1/-2/-3  the option changes the starting/minimum protocol version\n"
        . "   -sni    additional handshakes that include TLS extension SNI\n"
        . "   -sig    additional handshakes that include TLS extension SignatureAlgorithms\n\n");
}

($desthost,$destport) = ($ARGV[0],$ARGV[1]);

if ( $destport<= 0 || $destport>=65535 ) {
   die("Invalid TCP Port number \"$destport\"!\n");
}

srand(time|$$); ## for simple server response probing,
                ## ClientHello.Random will not need quality.

$peer_desc = $desthost . ":" . $destport ;

$tls_ctype_ccs       = "\x14";
$tls_ctype_alert     = "\x15";
$tls_ctype_handshake = "\x16";
$tls_ctype_appdata   = "\x17";

%tls_signature_algorithms = (
   "(rsa/md5)",    "\x01\x01",
   "(rsa/sha1)",   "\x02\x01",
   "(rsa/sha256)", "\x04\x01",
   "(rsa/sha384)", "\x05\x01"
);

%ssl_protocol_versions = (
   "0", "SSLv3",
   "1", "TLSv1.0",
   "2", "TLSv1.1",
   "3", "TLSv1.2"
);

%ssl_alert_levels = (
   "1", "warning",
   "2", "FATAL"
);

%ssl_alert_descriptions = (
   "0", "close_notify",
  "10", "unexpected_message",
  "20", "bad_record_mac",
  "21", "decryption_failed",
  "22", "record_overflow",
  "30", "decompression_failure",
  "40", "handshake_failure",
  "41", "no_certificate",
  "42", "bad_certificate",
  "43", "unsupported_certificate",
  "44", "certificate_revoked",
  "45", "certificate_expired",
  "46", "certificate_unknown",
  "47", "illegal_parameter",
  "48", "unknown_ca",
  "49", "access_denied",
  "50", "decode_error",
  "51", "decrypt_error",
  "60", "export_restriction",
  "70", "protocol_version",
  "71", "insufficient_security",
  "80", "internal_error",
  "86", "inappropriate_fallback",
  "90", "user_cancelled",
 "100", "no_renegotiation",
 "110", "unsupported_extension",
 "111", "certificate_unobtainable",
 "112", "unrecognized_name",
 "113", "bad_certificate_status_response",
 "114", "bad_certificate_hash_value",
 "115", "unknown_psk_identity"
);

%ssl_cipher_suites = (
 # relevant cipher suites from rfc2246 / TLSv1.0
 # https://tools.ietf.org/html/rfc2246#appendix-A.5
 "0x00,0x01", "TLS_RSA_WITH_NULL_MD5",
 "0x00,0x02", "TLS_RSA_WITH_NULL_SHA",
 "0x00,0x03", "TLS_EXPORT_WITH_RC4_40_MD5",
 "0x00,0x04", "TLS_RSA_WITH_RC4_128_MD5",
 "0x00,0x05", "TLS_RSA_WITH_RC4_128_SHA",
 "0x00,0x06", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
 "0x00,0x07", "TLS_RSA_WITH_IDEA_CBC_SHA",
 "0x00,0x08", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
 "0x00,0x09", "TLS_RSA_WITH_DES_CBC_SHA",
 "0x00,0x0a", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
 "0x00,0x16", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",

 # relevant cipher suites from rfc3268
 # https://tools.ietf.org/html/rfc3268#page-3
 "0x00,0x2f", "TLS_RSA_WITH_AES128_CBC_SHA",
 "0x00,0x33", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
 "0x00,0x35", "TLS_RSA_WITH_AES256_CBC_SHA",
 "0x00,0x39", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"

);




sub build_tls_record
{
   $l_pdu_ctype         = $_[0];
   $l_pdu_minor_version = $_[1];
   $l_pdu_body          = $_[2];

   $l_pdu = $l_pdu_ctype . "\x03" . pack("C1",$l_pdu_minor_version);
   $l_pdu .= pack("n1",length($l_pdu_body)) . $l_pdu_body;

   return($l_pdu);

} ### end sub build_tls_record()


sub build_clienthello
{
   $l_proto_minor_version = $_[0]; ## only the minor number 0=SSLv3, 3=TLSv1.2
   $l_cipher_suites       = $_[1]; ## the cipher suites to include 
   $l_sni_hostname        = $_[2]; ## the server hostname for TLSext SNI
   $l_sig_algs            = $_[3]; ## data for TLSext signature_algorithms

   $l_pdu_body = "\x03" . pack("C1", $l_proto_minor_version); ## client_version
   for ( $l_i=0 ; $l_i<16 ; $l_i++ ) { ## ClientHello.Random 
       $l_pdu_body .= pack("S1",rand(65536));
   }
   $l_pdu_body .= "\x00"; ## ClientHello.SessionID (none)
   ## TLS cipher suites
   $l_pdu_cs = "\x00\x2f\x00\x35\x00\x05\x00\x04\x00\x0a";
   $l_pdu_body .= pack("n1", length($l_pdu_cs)) . $l_pdu_cs;
   ## TLS compression algs
   $l_pdu_body .= "\x01\x00";   ## Null compression alg

   $l_tlsext_body = "";

   if ( $l_sni_hostname ne "" ) {
      $l_tlsext_sni_inner = "\x00" . pack("n1",length($l_sni_hostname)) . $l_sni_hostname;
      $l_tlsext_sni_body = pack("n1", length($l_tlsext_sni_inner)) . $l_tlsext_sni_inner;
      $l_tlsext_sni = "\x00\x00" . pack("n1", length($l_tlsext_sni_body)) . $l_tlsext_sni_body;
      $l_tlsext_body .= $l_tlsext_sni;
   }

   if ( $l_sig_algs ne "" ) {
      @l_algs = split(/,/,$l_sig_algs);
      $l_tlsext_sig_inner = "";
      while ( $l_alg = shift(@l_algs) ) {
	 if ( $tls_signature_algorithms{$l_alg} ne "" ) {
	    $l_tlsext_sig_inner .= $tls_signature_algorithms{$l_alg};
         }
      }
      if ( $l_tlsext_sig_inner ne "" ) {
         ## $l_tlsext_sig_inner = "\x04\x01\x05\x01\x02\x01";
         $l_tlsext_sig_body  = pack("n1", length($l_tlsext_sig_inner)) . $l_tlsext_sig_inner;
         $l_tlsext_sig      = "\x00\x0d" . pack("n1", length($l_tlsext_sig_body)) . $l_tlsext_sig_body;
         $l_tlsext_body .= $l_tlsext_sig;
      }
   }

   if ( $l_tlsext_body ne "" ) {
      $l_tlsext    = pack("n1", length($l_tlsext_body)) . $l_tlsext_body;
      $l_pdu_body .= $l_tlsext;
   }

   $l_pdu = "\x01" . "\x00" . pack("n1",length($l_pdu_body)) . $l_pdu_body;

   return( $l_pdu );

} ### end sub build_clienthello()


$sockaddr   = 'S n a4 x8';
$INADDR_ANY = pack("C C C C", 0, 0, 0, 0);
$AF_INET    = 2;

sub clienthello_server_response
{
   $l_rc = 1; ## default: failure

   $l_desthost = $_[0];
   $l_destport = $_[1];
   $l_clienthello = $_[2];
   $l_peerdesc = $l_desthost . ":" . $l_destport;

   $l_port = $l_destport;
   ($l_dum1,$l_dum2,$l_port) = getservbyname($l_destport,'tcp') unless $l_destport =~ /^\d+$/;
   if ( $l_desthost =~ m/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ ) {
       # IPv4 address -- no lookup
       $l_destaddr  = pack('C4', $1, $2, $3, $4);
   } else {
       ($l_dum1,$l_dum2,$l_dum3,$l_dum4,$l_destaddr) = gethostbyname($l_desthost);
   }

   $l_destsock = pack($sockaddr, $AF_INET, $l_port, $l_destaddr);

   print(STDERR "       ${l_peerdesc}...");

   if ( !socket( l_S, $AF_INET, $SOCK_STREAM, $tcp_proto ) ) {
      print(STDERR "\nsocket() failed: $!\n");
      goto leave_clean;
   }

   if ( ! connect( l_S, $l_destsock ) ) {
      print(STDERR "\nconnect(${l_peerdesc}) failed: $!\n");
      goto leave;
   }

   printf(STDERR " sending ClientHello (len=%d)\n", length($l_clienthello) );

   binmode(l_S);      ## switch socket to binary
   select(l_S); $|=1; ## switch socket to non-blocking
   select(STDERR);    ## make STDERR default fileselector for print

   print(l_S $l_clienthello);

   ## build select() mask
   $l_rin = '';
   vec($l_rin, fileno(l_S), 1) = 1;
   $l_timeout = 2; ## wait at most 2 seconds by default
   ($l_nfound,$l_timeleft) = select($l_rout=$l_rin, undef, $l_eout=$l_rin, $l_timeout); 

   $l_response_len = 0;
   if ( 0==$l_nfound ) {
       print(STDERR "   FAIL: (server did not respond within timeout ($l_timeout sec)).\n");
   } else {
      ## non-blocking read (this is after select() readable wakeup)
      $l_response_len = sysread(l_S, $l_response, 16384);
      if ( 0==$l_response_len ) {
         print(STDERR "   FAIL: (server silently closed network connection)\n");
      }
   }

   if ( $l_response_len > 0 ) {
       if ( 22==ord($l_response) && $l_response_len>9
            && 2==ord(substr($l_response,5)) ) {
          ## ServerHello response
          $l_rc = 0;
          $l_srv_version_maj = ord(substr($l_response,9));
	  $l_srv_version_min = ord(substr($l_response,10));
	  $l_srv_version_txt = "";
	  if ( $l_srv_version_maj == "3" ) {
	      $l_srv_version_txt = $ssl_protocol_versions{$l_srv_version_min};
	  }
	  if ( $l_srv_version_txt eq "" ) { $l_srv_version_txt = "???"; }
          
          printf(STDERR "   OK: ServerHello.server_version=(%d,%d) = (%s)\n",
		 $l_srv_version_maj, $l_srv_version_min, $l_srv_version_txt );
	  #
	  # determine server-selected TLS cipher suite (which follows session_id)
	  $l_srv_cs_offset = 9+2+32;
	  $l_sessid_len = ord(substr($l_response,$l_srv_cs_offset,1));
	  $l_srv_cs_offset++; # skip session_id vector length
          if ( $l_sessid_len>0 && $l_sessid_len<=32 ) {
	      $l_srv_cs_offset += $l_sessid_len;
	  }
	  $l_srv_cs_msb = ord(substr($l_response,$l_srv_cs_offset,1));
          $l_srv_cs_lsb = ord(substr($l_response,$l_srv_cs_offset+1,1));
          $l_cipher_suite = sprintf("0x%02x,0x%02x", $l_srv_cs_msb, $l_srv_cs_lsb);
          $l_srv_csname = $ssl_cipher_suites{$l_cipher_suite};
          printf(STDERR "        ServerHello.cs={ %s }  %s\n",
                 $l_cipher_suite, $l_srv_csname );
	     
       } elsif ( 21==ord($l_response) ) {
          ## SSL/TLS Alert Response
          print(STDERR  "   FAIL: Alert response: ");

          if ( 7==length($l_response) ) {
             $l_alert_level = ord(substr($l_response,5));
             $l_alert_desc  = ord(substr($l_response,6));
	     $l_alert_level_txt = $ssl_alert_levels{$l_alert_level};
	     if ( $l_alert_level_txt eq "" ) { $l_alert_level_txt = "???"; }
	     $l_alert_desc_txt = $ssl_alert_descriptions{$l_alert_desc};
	     if ( $l_alert_desc_txt eq "" ) { $l_alert_desc_txt = "???"; }
             printf(STDERR "level=%s(%d), desc=%s(%d)",
                    $l_alert_level_txt, $l_alert_level,
		    $l_alert_desc_txt, $l_alert_desc );
          }
          print(STDERR "\n");
       }
   }

leave:
    close(l_S);

leave_clean:
    return $l_rc;

} ### end sub clienthello_server_response()


#
# A few platform-specific constants
# (some are platform-specific, e.g. SOCK_STREAM, SO_REUSEADDR
#  some are host-byte-order (e.g. SOL_SOCKET))
#
$OS=`uname -s`; $OS =~ tr/\r\n//d;


$EINTR=4;
$EPIPE=29;
$SOCK_STREAM=1;
$SOL_SOCKET=1  if ( $OS eq "Linux" );
$SOCK_STREAM=1 if ( $OS eq "HP-UX" || $OS eq "Linux" );
$SOCK_STREAM=2 if ( $OS eq "IRIX" || $OS eq "SunOS" );
$SOL_SOCKET=65535 if ( $OS eq "HP-UX" || $OS eq "SunOS" );
$SO_REUSEADDR=4 if ( $OS eq "HP-UX" || $OS eq "SunOS" );
$SO_REUSEADDR=2 if ( $OS eq "Linux" );


#
# prepare data structures for IPv4 socket calls.
#


$myname=`hostname`;
$myname =~ tr/\r\n//d;
($name,$aliases,$tcp_proto) = getprotobyname('tcp');


# ensure that STDERR is set to non-blocking/non-buffered
#
select(STDERR); $|=1;


for ( $protovers = $min_proto_version ; $protovers<4 ; $protovers++ ) {

   printf(STDERR " %s: record=(3,%d), ClientHello=(3,%d) no TLS extensions\n",
                 $ssl_protocol_versions{$protovers},
		 $min_proto_version, $protovers );
   $client_hello = &build_clienthello( $protovers, "", "", "" );
   $tls_pdu      = &build_tls_record( $tls_ctype_handshake, $min_proto_version, $client_hello );

   clienthello_server_response( $desthost, $destport, $tls_pdu );

   if ( $try_with_tlsext_sni ) {
      printf(STDERR " %s: record=(3,%d), ClientHello=(3,%d) with TLS_ext SNI\n",
                     $ssl_protocol_versions{$protovers},
                     $min_proto_version, $protovers );

      $client_hello = &build_clienthello( $protovers, "", $desthost, "" );
      $tls_pdu      = &build_tls_record( $tls_ctype_handshake, $min_proto_version, $client_hello );

      clienthello_server_response( $desthost, $destport, $tls_pdu );
   }

   if ( $try_with_tlsext_sig ) {
      printf(STDERR " %s: record=(3,%d), ClientHello=(3,%d) with TLS_ext SIG_ALGS\n",
                     $ssl_protocol_versions{$protovers},
                     $min_proto_version, $protovers );

      $client_hello = &build_clienthello( $protovers, "", "", "(rsa/sha256),(rsa/sha384),(rsa/sha1)" );
      $tls_pdu      = &build_tls_record( $tls_ctype_handshake, $min_proto_version, $client_hello );

      clienthello_server_response( $desthost, $destport, $tls_pdu );
   }

   if ( $try_with_tlsext_sni && $try_with_tlsext_sig ) {
      printf(STDERR " %s: record=(3,%d), ClientHello=(3,%d) with TLS_ext SNI & SIG_ALGS\n",
                     $ssl_protocol_versions{$protovers},
                     $min_proto_version, $protovers );

      $client_hello = &build_clienthello( $protovers, "", $desthost, "(rsa/sha256),(rsa/sha384),(rsa/sha1)" );
      $tls_pdu      = &build_tls_record( $tls_ctype_handshake, $min_proto_version, $client_hello );

      clienthello_server_response( $desthost, $destport, $tls_pdu );
   }

}

