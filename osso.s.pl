#!/usr/bin/perl -w
#
=pod

=head1 LICENSE

    OSSO: Open Source Signalling Object by Orlangio
    Copyright (C) 2017  Orlandi Giovanni

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


=head1 AVAILABILITY
    Latest version available at:
      https://github.com/orlangio/osso

=head1 SYNOPSIS

  FIELD TYPE:
    REQUEST-TYPE : ALL UPPERCASE CODE (USUALLY 4 CHAR)
      EXAMPLE: WAIT / STAT / INCR / UPTO / DUMP / EXEC / PURG

    $oid : OBJECT IDENTIFIER : STRING NOT CONTAINING "FIELD SEPARATOR CHAR" OR "ASSIGN CHAR"
    $ovn : OBJECT VERSION NUMBER : UNSIGNED INTEGER
    $oem : OBJECT EMBEDDED MESSAGE : STRING NOT CONTAINING FIELD SEPARATOR CHAR
      NOTE: IF MESSAGE STRING BEGIN WITH "BASE64 SIGNAL CHAR" IT IS BASE64 ENCODED
  FIELD SEPARATOR CHAR: ~ : Char Code (127)
    MANDATORY: This Char Code (126) could not appear on any other port of $oid / $ovn / $oem
  ASSIGN CHAR: = : Char Equal Sign
  BASE64 SIGNAL CHAR: % : Char Code (37)
  MAIN MESSAGE FORMAT:
    REQUEST-TYPE ~ $oid=$ovn=$oem ~ $oid=$ovn=$oem

# WHEN an object increment, signal to all clients
# FOREACH client SIGNAL
  OBJECT MESSAGE FORMAT
    
    {^ any text ^}   should not contain FIELD SEPARATOR < ~ >   chr(126)
    {% base 64  %}   should contain base64 of string

COMMON BASE64 FORMAT 

SPECIAL BASE64 FORMAT
       3 CHAR : A_1-A_8   +   B_1-B_8   +   C_1-C_8
       PREFIX : A_7-A_8   +   B_7-B_8   +   C_7-C_8
   FIRST CHAR : A_1-A_6
  SECOND CHAR : B_1-B_6
   THIRD CHAR : C_1-C_6
  
  BIT CHAR CODES : 59-122    =>    VALUES:   CODE & -65
  BASE64 3 CHAR BA1-BA8 + BB1-BB8 + BC1-BC8  =>   BA1-BA6 / BA7-BA8+BB1-BB4 / BB5-BB8+BC1-BC2 / BC3-BC8
  BASE64 2 CHAR BA1-BA8 + BB1-BB8            =>   BA1-BA6 / BA7-BA8+BB1-BB4 / BB5-BB8+00               
  BASE64 1 CHAR BA1-BA8                      =>   BA1-BA6 / BA7-BA8+0000                               

  BASE64 3 CHAR Ab1-Ab8 + Bb1-Bb8 + Cb1-Cb8  =>   Ab7-Ab8+Bb7-Bb8+Cb7-Cb8 / Ab1-Ab6 / Bb1-Bb6 / Cb1-Cb6
  BASE64 2 CHAR BA1-BA8 + BB1-BB8            =>   Ab7-Ab8+Bb7-Bb8     +00 / Ab1-Ab6 / Bb1-Bb6
  BASE64 1 CHAR BA1-BA8                      =>   Ab7-Ab8           +0000 / Ab1-Ab6

  OPERATIVE CONSTANTS
    MAXLEN : Maximum UDP received message lenght, this affect also OBJECT EMBEDDED MESSAGE lenght
    serverPort : UDP port to listen into
    serverName : OSSO

  SPECIAL CHARS
    ~ ` \ ^
    CODE  32-125 ==     CODE  32-125    exclude 92/96
    CODE 160-253 == ` + CODE  32-125    exclude 92/96   aka   230/234
    CODE 126-159 == \ + CODE  32- 65
    CODE   0- 31 == \ + CODE  68-99
    CODE 254-255 == \ + CODE  68-99
    CODE      92 == \ + CODE  96-97
    CODE      94 == \ + CODE  96-97
    CODE      96 == \ + CODE  96-97
    CODE     126 == \ + CODE  98-99
=cut
#
#  ACCEPTABLE MESSAGES
#
#  WAIT ~ $oid=$ovn ~ $oid=$ovn ~ $oid=$ovn
#  UPTO ~ $oid=$ovn=message
#  INCR ~ $oid=$ovn=message ~ $oid=$ovn=message ~ $oid=$ovn=message
#
#  LIMITS:
#  $oid could not contain equal sign = neither FIELD SEPARATOR ~
#  $ovn thinked as integer (incrementable)
#  
my $serverName = "OSSO" ;
my $serverAddr = "127.0.0.1" ;
my $serverPort = 3777 ;
my $MAXLEN = 3777 ;

my $GLB_discardTime = 24 ;   # silently discard client request after 24 seconds elapsed

# array of clients call time
my @clientTimes = ( time()+99000999 ) ;   # reserve clientId 0
my $GLB_maxClients = 0 ;   # just clientId zero
# array of clients peer address
my @clientPeerAddresses = ( 0 ) ;
# array of clients objects-list
my @clientObjectLists = ( 0 ) ;

# Hash for each objectId of list of clients waiting signals
my %objectClientList = ( ) ;
my %objectVersionNumber = ( ) ;
my %objectEmbeddedMessage = ( ) ;

my $GLB_time ;


use IO::Socket;



logMessage( "$serverName CONNECT TO: $serverPort" ) ;
$sock = IO::Socket::INET->new(LocalAddr => $serverAddr, LocalPort => $serverPort, Proto => "udp")
    or die "Couldn't be a udp server on port $serverPort : $@\n";


my $timeout  = pack( 'l!l!', 4, 0 );   # seconds, microseconds
$sock->setsockopt( SOL_SOCKET, SO_RCVTIMEO, $timeout ) ;

while(   1   ) {
    $GLB_time = time() ;
    my $newmsg ;
    unless( $sock->recv( $newmsg, $MAXLEN) ) {
      purgeOldClients() ;
      next ;
    }
    my($port, $ipaddr) = sockaddr_in($sock->peername);
    $maip = inet_ntoa($ipaddr);

    if( ! defined $newmsg ) {
      logMessage( "RECEIVED EMPTY MESSAGE" ) ;
      purgeOldClients() ;
      next ;
    }
    print "Client $maip:$port said ``$newmsg''\n";

    my ( $cmd, $data ) = split( /~/, $newmsg, 2 ) ;

    if( ! defined $cmd ) {
      logMessage( "RECEIVED EMPTY CMD" ) ;
      purgeOldClients() ;
    } elsif( $cmd eq 'WAIT' ) {
      logMessage( "WAIT MESSAGE: $data" ) ;
      insertNewClient( $sock->peername, $data ) ;
    } elsif( $cmd eq 'STAT' ) {
      logMessage( "STAT MESSAGE: $data" ) ;
      $id = insertNewClient( $sock->peername, $data ) ;
      signalClient( $id, "STAT" )  if( $id ) ;
    } elsif( $cmd eq 'DUMP' ) {
      print "GLB_maxClients: $GLB_maxClients\n" ;
      my $safeTime = $GLB_time-$GLB_discardTime ;

      for( my $clientId = 1 ; $clientId <= $GLB_maxClients ; $clientId++ ) {
        $diff =   $clientTimes[$clientId] - $safeTime ;
        print "client: $clientId   diff time: $diff\n" ;
      }
      foreach my $key (sort(keys %objectClientList)) {
        print $key, '=', $objectVersionNumber{$key}, " ", $objectClientList{$key}, "\n";
      }
      
    } elsif( $cmd eq 'PURG' ) {
      purgeOldClients() ;
    } elsif( $cmd eq 'UPTO' ) {
      my ( $oid, $upto ) = split( /=/, $data ) ;
      logMessage( "UPTO MESSAGE: $oid/$upto" ) ;
      letObjectExists( $oid ) ;
      $objectVersionNumber{$oid}=$upto;
      signalObject( $oid ) ;
      replyClient( $sock->peername, "UPTO~OK" ) ;
    } elsif( $cmd eq 'INCM' ) {
      my ( $oid_oem ) = split( /~/, $data ) ;
      logMessage( "INCM MESSAGE: $oid_oem [$data/$newmsg]" ) ;
      my ( $oid, $oem ) = split( /=/, $oid_oem, 2 ) ;
      letObjectExists( $oid ) ;
      $objectVersionNumber{$oid}++ ;
      $objectEmbeddedMessage{$oid} = "=$oem" ;
      signalObject( $oid ) ;
      replyClient( $sock->peername, "INCR~OK" ) ;
    } elsif( $cmd eq 'INCR' ) {
      my ( $oid ) = split( /~/, $data ) ;
      logMessage( "INCR MESSAGE: $oid [$data/$newmsg]" ) ;
      letObjectExists( $oid ) ;
      $objectVersionNumber{$oid}++ ;
      signalObject( $oid ) ;
      replyClient( $sock->peername, "INCR~OK" ) ;
    } else {
      logMessage( "UNK MESSAGE: $newmsg" ) ;
      replyClient( $sock->peername, "UNKN~$newmsg" ) ;
    }
} 


sub logMessage {
  my $message = shift ;
  print "$message\n" ;
}

sub letObjectExists {
  my $objectId = shift || return ;
  if( ! defined $objectVersionNumber{$objectId} ) {
    $objectVersionNumber{$objectId} = 0 ;
    $objectClientList{$objectId} = '' ;
    $objectEmbeddedMessage{$objectId} = '' ;
  }
}

# One object is updated, signal to all clients
sub signalObject {
  my $objectId = shift || die 'Error: missing signalObject:objectId' ;
  foreach my $clientId ( split( /:/, $objectClientList{$objectId} ) ) {
    if( $clientId ) {
      logMessage( "signalObject:$objectId, SIGNALLING TO client:$clientId" ) ;
      signalClient( $clientId ) ;
    }
  }
}

# MANAGE A LIST OF oid=ovn FOR THIS CLIENT
sub insertNewClient {
  my $newClientAddress = shift || die 'Error: missing insertNewClient:clientAddress' ;
  my $newClientObjectList = shift || "" ;

  logMessage( "insertNewClient" ) ;

  purgeOldClients() ;   # this function set $GLB_goodClientId
  my $clientId = $GLB_goodClientId ;
  logMessage( "insertNewClient:Id:$clientId" ) ;
  $GLB_maxClients =   $clientId > $GLB_maxClients   ?   $clientId : $GLB_maxClients ;

  $clientTimes[$clientId] = $GLB_time ;
  $clientPeerAddresses[$clientId] = $newClientAddress ;
  $clientObjectLists[$clientId] = $newClientObjectList ;
  my $letSignal = 0 ;
  foreach my $oid_ovn ( split( /~/, $newClientObjectList ) ) {
    my ( $oid, $ovn ) = split( /=/, $oid_ovn ) ;
    letObjectExists($oid) ;
    if( $objectVersionNumber{$oid} > $ovn ) {
      $letSignal = 1 ;
    }
    $objectClientList{$oid} .= ":$clientId:" ;
  }
  if( $letSignal ) {
      logMessage( "insertNewClient:immediateSignal:$clientId" ) ;
      signalClient( $clientId ) ;
      return 0 ;   # JUST SIGNALED, CLIENT NO MORE EXISTS
  }

  logMessage( "insertNewClient:return:$clientId" ) ;
  return $clientId ;
}


# purge old clients when timeout, set GLB_goodClientId to new id or reuse empty id
sub purgeOldClients {
  my $safeTime = $GLB_time-$GLB_discardTime ;
  $GLB_goodClientId = $GLB_maxClients + 1 ;   # maybe we need a new insert
  logMessage( "purgeOldClients:$GLB_goodClientId" ) ;

  for( my $clientId = 1 ; $clientId <= $GLB_maxClients ; $clientId++ ) {
    if(   $clientTimes[$clientId] < $safeTime   ) {
      $GLB_goodClientId = $clientId ;   # no need for new insert
      if(   $clientTimes[$clientId]   ) {
        signalClient( $clientId, 'NONE' ) ;   # just timeout no real signals
      }
    }
  }

}



sub signalClient {
  my $clientId = shift || die 'Error: missing signalClient:clientId' ;
  my $signalType = shift || 'WAKE' ;
  my $flags = 0 ;

  my $clientAddress = $clientPeerAddresses[$clientId] ;
  $clientTimes[$clientId] = 0 ;
  my $clientReply = $signalType ;
  foreach my $oid_ovn ( split( /~/, $clientObjectLists[$clientId] ) ) {
    my ( $oid, $ovn ) = split( /=/, $oid_ovn ) ;
    $ovn = $objectVersionNumber{$oid} || 0 ;
    $oem = $objectEmbeddedMessage{$oid} ;
    $clientReply .= "~$oid=$ovn$oem" ;
    $objectClientList{$oid} =~ s/:$clientId:// ;
  }
  $clientObjectLists[$clientId] = '' ;
  send( $sock, $clientReply, $flags, $clientAddress ) ;
  logMessage( "signalClient:$clientId" ) ;

  return ;
}

sub replyClient {
  my $clientPeer = shift || die 'Error: missing replyClient:clientPeer' ;
  my $clientReply = shift ;
  my $flags = 0 ;
  send( $sock, $clientReply, $flags, $clientPeer ) ;
}

