##################
## Module Name     --  websocket
## Original Author --  Emmanuel Frecon - emmanuel@sics.se
## Patches         --  Adrián Medraño Calvo - amcalvo@prs.de
## Refactoring     --  Braden R. Napier -- bradynapier@gmail.com
## Description:
##
##    This library implements a WebSocket client library on top of the
##    existing http package.  The library implements the HTTP-like
##    handshake and the necessary framing of messages on sending and
##    reception.  The library is also server-aware, i.e. implementing
##    the slightly different framing when communicating from a server
##    to a client.  Part of the code comes (with modifications) from
##    the following Wiki page: http://wiki.tcl.tk/26556

##
##################

package require Tcl 8.6

package require http 2.7;  # Need keepalive!
package require sha1
package require base64

# IMPLEMENTATION NOTES:
#
# The rough idea behind this library is to misuse the standard HTTP
# package so as to benefit from all its handshaking and the solid
# implementation of the HTTP protocol that it provides.  "Misusing"
# means requiring the HTTP package to keep the socket alive, which
# giving away the opened socket to the library once all initial HTTP
# handshaking has been performed.  From that point and onwards, the
# library is responsible for the framing of fragments of messages on
# the socket according to the RFC.
#
# The library almost solely uses the standard API of the HTTP package,
# thus being future-proof as much as possible as long as the HTTP
# package is kept backwards compatible. HOWEVER, it requires to
# extract the identifier of the socket towards the server from the
# state array. This extraction is not officially specified in the man
# page of the library and could therefor be subject to change in the
# future.


namespace eval ::websocket {
  variable WS
  if { ! [info exists WS] } {
    array set WS {
      loglevel       "error"
      maxlength      16777216
      ws_magic       "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
      ws_version     13
      id_gene        0
      whitespace     " \t"
      tchar          {!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~}
      -keepalive     30
      -ping          ""
  	}
  	# Build ASCII case-insensitive mapping table. See
  	# <http://tools.ietf.org/html/rfc6455#section-2.1>.
  	for {set i 0x41} {$i <= 0x5A} {incr i} {
	    lappend WS(lowercase) [format %c $i] [format %c [expr {$i + 0x20}]]
  	}
  	unset i
  	variable libdir [file dirname [file normalize [info script]]]
  }
}

namespace eval ::websocket::sockets {}

::oo::class create ::websocket::socket {}

::oo::define ::websocket::socket {
  variable URL STATE SOCK HANDLER SERVER TIMEOUT NONCE
  variable AFTER_IDS PEER_NAME SOCK_NAME
  variable READ_MODE FRAGMENT WRITE_MODE
}

::oo::define ::websocket::socket constructor { schema } {
  set STATE OPENING
  set SOCK  {}
  set PEER_NAME  {}
  set SOCK_NAME  {}
  set READ_MODE  {}
  set WRITE_MODE {}
  set FRAGMENT   {}
  set AFTER_IDS  [dict create]

  if { [dict exists $schema server] } {
    set SERVER [dict get $schema server]
  } else { set SERVER 0 }

  set TIMEOUT [dict get $schema timeout]
  set URL     [dict get $schema url]
  set HANDLER [dict get $schema handler]
  set NONCE   [dict get $schema nonce]

  # Adding our own handler to intercept the socket once connection
  # has been opened and established properly would be logical, but
  # does not work in practice since this forces the HTTP library to
  # perform a HTTP 1.0 request. Instead, we arrange to be called
  # back via -command. We force -keepalive to make sure the HTTP
  # library does not insert a "Connection: close" directive in the
  # headers, and really make sure to do whatever we can to have a
  # HTTP 1.1 connection.
  set cmd [list ::http::geturl [::websocket::formaturl $URL] \
    -keepalive 1 \
    -protocol  1.1 \
    -headers   [dict get $schema headers] \
    -command   [namespace code [list my Connected]]
  ]

  my open $cmd
}

::oo::define ::websocket::socket method open { cmd } {
  try {
    if { $TIMEOUT > 0 } {
      # Add a HTTP Timeout to be safe if our timeout fails
      lappend cmd -timeout [expr { $TIMEOUT + 5000 }]
    }

    set STATE CONNECTING
    set token [try $cmd]

    if { $TIMEOUT > 0 } {
      dict set AFTER_IDS open_timeout [after $TIMEOUT [namespace code [list my Timeout $token]]]
    }

    my UpdateSocket $token

  } on error {result options} {
    my Error "Error while opening WebSocket connection to $URL : $result" $result $options
    if { [info exists token] } {
      ::http::cleanup $token
    }
    my Finished
  }
}

::oo::define ::websocket::socket method UpdateSocket { token } {
  set sock [array get $token sock]
  if { $sock eq {} } {
    throw error "Socket Not Found in HTTP Token"
  } else {
    set SOCK [dict get $sock sock]
  }
}

::oo::define ::websocket::socket method Timeout { token } {
  try {
    set STATE TIMEOUT
    if { [dict exists $AFTER_IDS open_timeout] } {
      after cancel [dict get $AFTER_IDS open_timeout]
      dict unset AFTER_IDS open_timeout
    }
    ::http::reset   $token timeout
    ::http::cleanup $token
  } on error {result options} {
    my Error "While Handling a WebSocket Timeout" $result $options
  }
  catch { my UpdateSocket $token }
  my dispatch timeout "WebSocket Connection Timed Out"
  my disconnect
}

::oo::define ::websocket::socket method Finished {} {
  my disconnect
  [self] destroy
}

::oo::define ::websocket::socket method Connected { token } {
  try {
    if { [::http::status $token] eq "timeout" } {
      my Timeout $token
    } else {
      if { [dict exists $AFTER_IDS open_timeout] } {
        after cancel [dict get $AFTER_IDS open_timeout]
        dict unset AFTER_IDS open_timeout
      }
      my UpdateSocket $token
      if { $SOCK eq {} } {
        throw SOCK_FAILED "Could not extract socket id from the HTTP Token $token"
      }
      set ncode [::http::ncode $token]
      if { $ncode == 101 } {
        set result   [ my ParseToken $token ]
        set unmapped [ ::websocket::unmap_socket $SOCK ]
        my Takeover $result
      } else {
        throw UNEXPECTED_NCODE "Received $ncode while expecting 101 when establishing connection with $URL"
      }
    }
  } on error {result options} {
    my Error "While Finishing a WebSocket Connection" $result $options
    my disconnect
  } finally {
    if { [info exists token] } {
      catch { ::http::cleanup $token }
    }
  }
}

::oo::define ::websocket::socket method ParseToken { token } {
  set headers [::http::meta $token]
  set result  [dict create]
  if { [dict exists $headers "Sec-WebSocket-Accept"] } {
    # Extact security handshake, check against what was expected
  	# and abort in case of mismatch.
    # Compute and compare security handshake
  	if { [::websocket::sec-websocket-accept $NONCE] ne [dict get $headers "Sec-WebSocket-Accept"] } {
  	  ::http::reset $token error
  	  throw NONCE_MISMATCH "While Handling Security Handshake (Sec-WebSocket-Accept)"
  	}
  }
  if { [dict exists $headers "Sec-WebSocket-Protocol"] } {
    # Extract application protocol information to pass further to
  	# handler.
  	dict set result proto [dict get $headers "Sec-WebSocket-Protocol"]
  }
  return $result
}

::oo::define ::websocket::socket method Takeover result {
  try {
    set STATE CONNECTED
    my GetSocketInfo

    chan configure $SOCK -translation binary -blocking 0
    chan event     $SOCK readable [namespace code [list my Receive $SOCK]]

    my dispatch connect $result
  }
}

::oo::define ::websocket::socket method GetSocketInfo {} {
  try {
    set sockinfo [chan configure $SOCK -peername]
    switch -- [llength $sockinfo] {
      1 { set PEER_NAME [lindex $sockinfo 0] }
      2 { set PEER_NAME [lindex $sockinfo 1] }
    }
    set sockinfo [chan configure $SOCK -sockname]
    switch -- [llength $sockinfo] {
      1 { set SOCK_NAME [lindex $sockinfo 0] }
      2 { set SOCK_NAME [lindex $sockinfo 1] }
    }
    return 1
  } on error {result options} {
    my Warn "While Getting Socket Information" $result $options
    return 0
  }
}

::oo::define ::websocket::socket method Receive { sock } {
  if { $SOCK ne $sock } {
    # This should never occur.
    my Warn "While Receiving from $sock" "Socket ID Mismatch $SOCK vs $sock"
  }
  if { [catch {read $sock 2} data] || [string length $data] != 2 } {
    if {[chan eof $sock]} {
	    set data "Socket closed."
	  }
    my close 1001
    return
  }

  # Handle the packet
  binary scan $data Su header
  set op_code  [expr { $header >> 8 & 0xf }]
  set mask     [expr { $header >> 7 & 0x1 }]
  set length   [expr { $header & 0x7f }]
  set reserved [expr { $header >> 12 & 0x7 }]

  puts "
    Op Code: $op_code
    Mask:    $mask
    Length:  $length
    Reserved: $reserved
  "
  if {
       $reserved
    || ( $op_code == 0 && $READ_MODE eq {} )
    || ( $op_code >  7 && ( ! ( $header & 0x8000 ) || $length > 125 ) )
    || $op_code ni [list 0 1 2 8 9 10]
  } {
    # Send close frame, reason 1002: protocol error
    my close 1002
    return
  }

  if { $READ_MODE eq {} } {
    set READ_MODE $op_code
  } elseif { $op_code == 0 } {
    set op_code $READ_MODE
  }

  # Get the extended length, if present
  if { $length == 126 } {
    if { [catch {read $sock 2} data] || [string length $data] != 2 } {
      my Error "While Reading from WebSocket" "Cannot read length from socket: $data"
      my close 1001
      return
    }
    binary scan $data Su length
  } elseif { $length == 127 } {
    if { [catch {read $sock 8} data] || [string length $data] != 8 } {
      my Error "While Reading from WebSocket" "Cannot read length from socket: $data"
      my close 1001
      return
    }
    binary scan $data Wu length
  }

  # Control frames use a separate buffer, since they can be
  # interleaved in fragmented messages.
  if { $op_code > 7 } {
    if { $length > 125 } {
	    my close 1009
	    return
	  }
	  set prev_fragment $FRAGMENT
    set FRAGMENT {}
  } else {
    if { [string length $FRAGMENT] + $length > $::websocket::WS(maxlength) } {
      my close 1009 "Limit $::websocket::WS(maxlength) exceeded"
      return
    } else {
      # ?
      set prev_fragment $FRAGMENT
    }
  }

  if { $mask } {
    # Get mask and data.  Format data as a list of 32-bit integer
    # words and list of 8-bit integer byte leftovers.  Then unmask
	  # data, recombine the words and bytes, and append to the buffer.
	  if { [catch {read $sock 4} data] || [string length $data] != 4 } {
      my Error "While Reading from WebSocket" "Cannot read mask from socket: $data"
      my close 1001 "Cannot read mask from socket: $data"
      return
    }
    binary scan $data Iu mask
    if { [catch {read $sock $length} data] } {
	    my Error "While Reading from WebSocket" "Cannot read fragment content from socket: $data"
	    my close 1001 "Cannot read fragment content from socket: $data"
	    return
  	}
  	append FRAGMENT [::websocket::Mask $mask $data]
  } else {
    if { [catch {read $sock $length} data] || [string length $data] != $length } {
      my Error "While Reading from WebSocket" "Cannot read fragment content from socket: $data"
      my close 1001 "Cannot read fragment content from socket: $data"
      return
    }
    append FRAGMENT $data
  }

  if { $SERVER } {

  } else {

  }

  set type [::websocket::Type $READ_MODE]

  if { $header & 0x8000 } {
    switch -- $op_code {
      1 { my ReceiveText   }
      2 { my ReceiveBinary }
      8 {
        # Close: decode, notify handler and close frame.
        if { [string length $FRAGMENT] >= 2 } {
          binary scan [string range $FRAGMENT 0 1] Su reason
          set msg [encoding convertfrom utf-8 [string range $FRAGMENT 2 end]]
          my close $reason $msg
        } else {
          my close
        }
        return
      }
      9 {
        # Ping: send pong back and notify handler since this
    		# might contain some data.
    		my ping
      }
      10 {
        # Pong
        my dispatch pong $FRAGMENT
      }
    }

    # Prepare for the next frame

    if { $op_code < 8 } {
      # Reinitialize
      set FRAGMENT  {}
      set READ_MODE {}
    } else {
      set FRAGMENT $prev_fragment
      if { $READ_MODE eq $op_code } {
        # non-interjected control frame, clear mode
        set READ_MODE {}
      }
    }

  } else {
    # Received Fragment
    puts "Received $length long $type fragment"
  }

}

::oo::define ::websocket::socket method ReceiveText {} {
  # Text: decode and notify handler
  set data $FRAGMENT
  set FRAGMENT {}
  my dispatch text [encoding convertfrom utf-8 $data]
}

::oo::define ::websocket::socket method ReceiveBinary {} {
  # Binary: notify handler, no decoding
  set data $FRAGMENT
  set FRAGMENT {}
  my dispatch binary $data
}

::oo::define ::websocket::socket method close { {code 1000} { reason {} } } {
  if { $STATE eq "CLOSED" } {
    # ?
    return 0
  }
  set STATE CLOSED
  if { $code == "" || ! [string is entier $code] } {
    my send 8
    my dispatch close {}
  } else {
    if { $reason eq {} } {
      switch -- $code {
        1000 { set reason "Normal Closure" }
        1001 { set reason "Endpoint going away" }
        1002 { set reason "Protocol Error" }
        1003 { set reason "Received incompatible data type" }
        1006 { set reason "Abnormal Closure" }
        1007 { set reason "Received data not consistent with type" }
        1008 { set reason "Policy violation" }
        1009 { set reason "Received message too big" }
        1010 { set reason "Missing extension" }
        1011 { set reason "Unexpected condition" }
        1015 { set reason "TLS handshake error" }
      }
    }
    set msg [binary format Su $code]
    append msg [encoding convertto utf-8 $reason]
    set msg [string range $msg 0 124] ; # Cut answer to make sure it fits!
    my send 8 $msg
    my dispatch close [list $code $reason]
  }
  my Disconnect
}

::oo::define ::websocket::socket method Disconnect {} {
  set STATE DISCONNECTED
  catch { chan close $SOCK }
  my dispatch disconnect
  [self] destroy
}

::oo::define ::websocket::socket method dispatch { type msg } {
  try {
    {*}$HANDLER [self] $type $msg
  } on error {result options} {
    my Error "While Calling the WebSocket Handler: $type" $result $options
  }
}

::oo::define ::websocket::socket method ping { {data {}} } {
  if { $data eq {} } { set data $FRAGMENT ; set FRAGMENT {} }
  my send 10 $data
  my dispatch ping $data
}

::oo::define ::websocket::socket method socket {} { return $SOCK }
::oo::define ::websocket::socket method state  {} { return $STATE }

::oo::define ::websocket::socket method send { type {msg {}} {final 1} } {
  if { $STATE ne "CONNECTED" } {
    return -1
  }
  # parse the type that is being sent
  if { ! [string is entier -strict $type] } {
    set op_code [::websocket::Type $type]
  } else {
    if { $type ni [list 1 2 8 9 10] } {
      set op_code -1
    } else { set op_code $type }
  }

  if { $op_code < 0 } {
    my Error "While Sending a Packet to the WebSocket" "Invalid Type should be one of text, binary, or ping | Received: $type"
    return
  }

  if { $WRITE_MODE ne {} && $WRITE_MODE > 0 } {
    if { $op_code ne $WRITE_MODE } {
      my Error "While Sending a Packet to the WebSocket" "Canno tchange type of message under continuation!"
      return
    }
    set op_code 0 ; # Continuation
  } else {
    set WRITE_MODE $op_code
  }

  set type [::websocket::Type $WRITE_MODE]

  if { $WRITE_MODE == 1 } {
    set msg [encoding convertto utf-8 $msg]
  }

  if { [string is true -strict $final] } {
    # Reset continuation state once sending last fragment of message.
    set WRITE_MODE {}
  }

  # Start assembling the header.
  set header [binary format c [expr { !!$final << 7 | $op_code }]]

  # Append the length of the message to the header. Small lengths
  # fit directly, larger ones use the markers 126 or 127.  We need
  # also to take into account the direction of the socket, since
  # clients shall randomly mask data.
  set mlength [string length $msg]
  if { $mlength < 126 } {
    set length $mlength
  } elseif { $mlength < 65536 } {
    set length 126
  } else { set length 127 }

  # Set mask bit and push regular length into header.
  if { $SERVER } {
    append header [binary format c $length]
  } else {
    append header [binary format c [expr { 1 << 7 | $length }]]
  }

  # Appends "longer" length when the message is longer than 125 bytes
  if { $mlength > 125 } {
    if { $mlength < 65536 } {
      append header [binary format Su $mlength]
    } else {
      append header [binary format Wu $mlength]
    }
  }

  # Add the masking key and perform client masking whenever relevant
  if { ! $SERVER } {
    set mask      [expr {int(rand()*(1<<32))}]
    append header [binary format Iu $mask]
    set msg       [::websocket::Mask $mask $msg]
  }

  # Send the (masked) frame
  try {
    puts -nonewline $SOCK $header$msg
    flush $SOCK
  } on error {result options} {
    my Error "While Sending a packet to the WebSocket" $result $options
    my close 1001
    return -1
  }

  return [string length $header$msg]
}


::oo::define ::websocket::socket method Error { while {result {}} {options {}} } {
  catch { uplevel #0 [list {*}$HANDLER $SOCK error $while $result $options] }
}

::oo::define ::websocket::socket method Warn { while {result {}} {options {}} } {
  catch { uplevel #0 [list {*}$HANDLER $SOCK warn $while $result $options] }
}


proc Receive args {
  puts "RECEIVE"
  puts $args
}
