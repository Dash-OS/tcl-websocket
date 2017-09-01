namespace eval ::websocket {}

# ::websocket::Mask -- Mask data according to RFC
#
#       XOR mask data with the provided mask as described in the RFC.
#
# Arguments:
#	mask	Mask to use to mask the data
#	dta	Bytes to mask
#
# Results:
#       Return the mask bytes, i.e. as many bytes as the data that was
#       given to this procedure, though XOR masked.
#
# Side Effects:
#       None.
proc ::websocket::Mask { mask data } {
  # Format data as a list of 32-bit integer
  # words and list of 8-bit integer byte leftovers.  Then unmask
  # data, recombine the words and bytes, and return
  binary scan $data I*c* words bytes

  set masked_words {}; set masked_bytes {}

  for {set i 0} {$i < [llength $words]} {incr i} {
	  lappend masked_words [expr {[lindex $words $i] ^ $mask}]
  }

  for {set i 0} {$i < [llength $bytes]} {incr i} {
	  lappend masked_bytes [expr {
	    [lindex $bytes $i] ^ ($mask >> (24 - 8 * $i))
	  }]
  }

  return [binary format I*c* $masked_words $masked_bytes]
}

proc ::websocket::Type { opcode } {
  if { ! [string is entier -strict $opcode] } {
    switch -glob -nocase -- $opcode {
      t* { return 1 }
      b* { return 2 }
      p* { return 9 }
    }
  } else {
    switch -- $opcode {
      1  { return text   }
      2  { return binary }
      8  { return close  }
      9  { return ping   }
      10 { return pong   }
      default { return <opcode-${opcode}> }
    }
  }
  return -1
}

# ::websocket::HTTPSocket -- Get socket from HTTP token
#
#       Extract the socket used for a given (existing) HTTP
#       connection.  This uses the undocumented index called "sock" in
#       the HTTP state array.
#
# Arguments:
#	token	HTTP token, as returned by http::geturl
#
# Results:
#       The socket to the remote server, or an empty string on errors.
#
# Side Effects:
#       None.
proc ::websocket::HTTPSocket { token } {
  upvar \#0 $token htstate
  if { [info exists htstate(sock)] } {
	  return $htstate(sock)
  } else {
	  #${log}::error "No socket associated to HTTP token $token!"
	  return
  }
}

#
#       Ensures a token is included in hdr's header field value.
#
# Arguments:
#       hdrsName Name of an array variable on caller's scope whose
#                keys are header names and values are header values.
#       hdr      Header name, matched case-insensitively.
#       token    Token to include.
#
# Results:
#       Nothing.
#
# Side Effects:
#       Modifies variable named hdrsName in caller's scope.
proc ::websocket::AddHeader { hdrsName hdr token {replace 0} } {
  ::upvar 1 $hdrsName headers
  if { $replace } {
    set header $token
  } else {
    if { [dict exists $headers $hdr] } {
      set header [dict get $headers $hdr]
      append header ", $token"
    } else {
      set header $otken
    }
  }
  dict set headers $hdr $header
}


# ::websocket::open -- Open connection to remote WebSocket server
#
#       Open a WebSocket connection to a remote server.  This
#       procedure takes a number of options, which mostly are the
#       options that are supported by the http::geturl procedure.
#       However, there are a few differences described below:
#       -headers  Is supported, but additional headers will be added internally
#       -validate Is not supported, it has no point.
#       -handler  Is used internally, so cannot be specified.
#       -command  Is used internally, so cannot be specified.
#       -protocol Contains a list of app. protocols to handshake with server
#
# Arguments:
#	url	WebSocket URL, i.e. led by ws: or wss:
#	handler	Command prefix to invoke on data reception or event occurrence
#	args	List of dashled options with their values, as explained above.
#
# Results:
#       Return the socket for use with the rest of the WebSocket
#       library, or an empty string on errors.
#
# Side Effects:
#       None.
proc ::websocket::open { url handler args } {
  variable WS
  # Control the geturl options that we can blindly pass to the
  # http::geturl call. We basically remove -validate, which has no
  # point and stop -handler which we will be using internally.  We
  # restrain the use of -timeout, implementing the timeout ourselves
  # to avoid the library to close the socket to the server.  We also
  # intercept the headers since we will be adding WebSocket protocol
  # information as part of the headers.
  set timeout -1
  set headers [dict create]
  set protos  [list]
  set nonce   {}
  foreach { k v } $args {
    set allowed 0
    foreach opt {bi* bl* ch* he* k* m* prog* prot* qu* s* ti* ty*} {
      if { [string match -nocase $opt [string trimleft $k -]] } {
	      set allowed 1
      }

    }
    switch -nocase -glob -- [string trimleft $k -] {
      he* {
    		# Catch the headers, since we will be adding a few
    		# ones by hand.
    		set headers $v
      }
      prot* {
    		# New option -protocol to support the list of
    		# application protocols that the client accepts.
    		# -protocol should be a list.
	      set protos $v
      }
      ti* {
    		# We implement the timeout ourselves to be able to
    		# properly cleanup.
    		if { [string is integer $v] && $v > 0 } {
    		  set timeout $v
    		}
      }
	    default {
    		# Any other allowed option will simply be passed
    		# further to the http::geturl call, to benefit from
    		# all its facilities.
    		lappend cmd $k $v
	    }
    }
  }

  # Construct the WebSocket part of the header according to RFC6455.
  # The NONCE should be randomly chosen for each new connection
  # established
  for { set i 0 } { $i < 4 } { incr i } {
    append nonce [binary format Iu [expr {int(rand()*4294967296)}]]
  }
  set nonce [::base64::encode $nonce]
  AddHeader headers "Connection" "Upgrade"   1
  AddHeader headers "Upgrade"    "websocket" 1
  AddHeader headers "Sec-WebSocket-Key"      $nonce 1
  AddHeader headers "Sec-WebSocket-Protocol" [join $protos ", "]       1
  AddHeader headers "Sec-WebSocket-Version"  $WS(ws_version)           1

  # Create the WebSocket Object which will coordinate from here
  set ws_sock [::websocket::socket create ::websocket::sockets::sock_[incr WS(id_gene)] [dict create \
    url     $url \
    headers $headers \
    handler $handler \
    timeout $timeout \
    nonce   $nonce
  ]]

  return $ws_sock
}

# Fool the http library by replacing the ws: (websocket) scheme
# with the http, so we can use the http library to handle all the
# initial handshake.
proc ::websocket::formaturl { url } { regsub -nocase {^ws} $url "http" }

# ::websocket::ASCIILowercase
#
#       Convert a string to ASCII lowercase.
#
#       See <http://tools.ietf.org/html/rfc6455#section-2.1>.
#
# Arguments:
#       str   The string to convert
#
# Results:
#       The string converted to ASCII lowercase.
#
# Side Effects:
#       None.
proc ::websocket::ASCIILowercase { str } {
  variable WS
  return [string map $WS(lowercase) $str]
}

# ::websocket::SplitCommaSeparated -- Extract elements from comma-separated headers
#
#       Extract elements from a comma separated header's value, ignoring empty
#       elements and linear whitespace.
#
#       See <http://tools.ietf.org/html/rfc7230#section-7>.
#
# Arguments:
#       value   A header's value, consisting of a comma separated list of
#               elements.
#
# Results:
#       A list of values.
#
# Side Effects:
#       None.
proc ::websocket::SplitCommaSeparated { csl } {
  variable WS
  set r [list]
  foreach e [split $csl ,] {
	  # Trim OWS.
	  set v [string trim $e $WS(whitespace)]
	  # There might be empty elements.
	  if {$v ne {}} { lappend r $v }
  }
  return $r
}

# ::websocket::sec-websocket-accept -- Construct Sec-Websocket-Accept field value.
#
#       Construct the value for the Sec-Websocket-Accept header field, as
#       defined by (RFC6455 4.2.2.5.4).
#
#       See <http://tools.ietf.org/html/rfc6455#section-4.2.2>.
#
# Arguments:
#       key     The value of the Sec-Websocket-Key header field in the client's
#               handshake.
#
# Results:
#       The value for the Sec-Websocket-Accept header field.
#
# Side Effects:
#       None.
proc ::websocket::sec-websocket-accept { key } {
  variable WS
  set sec ${key}$WS(ws_magic)
  return [::base64::encode [::sha1::sha1 -bin $sec]]
}

# Remove the socket from the socketmap inside the http
# library.  THIS IS UGLY, but the only way to make sure we
# really can take over the socket and make sure the library
# will open A NEW socket, even towards the same host, at a
# later time.
proc ::websocket::unmap_socket { sock } {
	if { [info vars ::http::socketmap] ne "" } {
    foreach k [array names ::http::socketmap] {
	    if { $::http::socketmap($k) eq $sock } {
	      unset ::http::socketmap($k)
	    }
    }
    return 1
	} else { return 0 }
}
