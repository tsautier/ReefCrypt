; FiSH 10 mIRC control script. The DLLs handle IRC encryption and decryption.
; The script manages keys, preferences, DH1080 notices and local display.

on *:START:fish10.start

alias -l fish10.start {
  if ($hget(reefcrypt.fish.runtime,initialized)) return
  var %exe.dir = $nofile($mircexe)
  var %engine = %exe.dir $+ fish_inject.dll
  set %FiSH_dll $qt(%exe.dir $+ fish_10.dll)
  set %blow_ini $iif($portable,%exe.dir,$mircdir) $+ blow.ini
  if (!$isfile(%engine)) || (!$isfile($noqt(%FiSH_dll))) {
    echo -s FiSH 10 could not find its DLLs next to mIRC.
    return
  }
  .dll $qt(%engine) _callMe
  .dll %FiSH_dll _callMe
  .dll %FiSH_dll FiSH_SetIniPath %blow_ini
  hadd -m reefcrypt.fish.runtime initialized 1
}

on *:UNLOAD:{
  if ($hget(reefcrypt.fish.runtime)) hfree reefcrypt.fish.runtime
  if ($hget(reefcrypt.fish.pending)) hfree reefcrypt.fish.pending
  if ($window(@FiSH-Key)) window -c @FiSH-Key
}

; Use the same NETWORK token as the DLL when mIRC normalizes its display name.
raw 005:*:{
  var %entry = $wildtok($1-,NETWORK=*,1,32)
  if ($len(%entry) > 8) hadd -m reefcrypt.fish.runtime $+(network.,$cid) $mid(%entry,9)
}

on *:DISCONNECT:{
  if ($hget(reefcrypt.fish.runtime)) hdel reefcrypt.fish.runtime $+(network.,$cid)
  if ($hget(reefcrypt.fish.pending)) hdel -w reefcrypt.fish.pending $+($cid,:*)
}

alias -l fish10.network {
  var %name = $hget(reefcrypt.fish.runtime,$+(network.,$cid))
  return $iif(%name != $null,%name,$network)
}

alias -l fish10.ready {
  if ($hget(reefcrypt.fish.runtime,initialized)) && ($fish10.network != $null) return $true
  echo -a FiSH 10 requires its DLLs and an IRC network name for this operation.
  return $false
}

alias -l fish10.context {
  if ($1 != $null) && ($1 != /query) return $1
  if ($query($active)) return $active
  if ($1 == $null) && ($chan($active)) return $active
}

alias -l fish10.target.valid {
  if ($1 == $null) return $false
  return $iif($regex($1,/^[^\x00-\x20\x7f\x2c:]+$/),$true,$false)
}

alias -l fish10.contact.key {
  if ($1 != $null) return $dll(%FiSH_dll,FiSH_GetKey10,$fish10.network $1 hex)
}

alias FiSH.setkey {
  if ($1 == $null) || ($2 == $null) {
    echo -a Usage $+ $chr(58) /FiSH.setkey <target> <key>
    return
  }
  var %target = $fish10.context($1)
  if ($fish10.target.valid(%target)) fish10.store.manual decode_utf8 %target $2-
}

alias FiSH.setkey_utf8 {
  if ($1 == $null) || ($2 == $null) {
    echo -a Usage $+ $chr(58) /FiSH.setkey_utf8 <target> <key>
    return
  }
  var %target = $fish10.context($1)
  if ($fish10.target.valid(%target)) fish10.store.manual raw_bytes %target $2-
}

alias -l fish10.store.manual {
  if (!$fish10.target.valid($2)) || ($3 == $null) return
  if (!$fish10.ready) return
  if ($dll(%FiSH_dll,FiSH_WriteKey10,$1 $fish10.network $2 $3-) == ok) {
    echo -a FiSH 10 saved the key for $2 $+ .
  }
  else echo -a FiSH 10 could not save the key for $2 $+ .
}

alias FiSH.showkey {
  var %target = $fish10.context($1)
  if (!$fish10.target.valid(%target)) || (!$fish10.ready) return
  if (!$fish10.contact.key(%target)) {
    echo -a FiSH 10 has no key for %target $+ .
    return
  }
  var %key = $dll(%FiSH_dll,FiSH_GetKey10,$fish10.network %target)
  if (!$window(@FiSH-Key)) window @FiSH-Key
  clear @FiSH-Key
  echo -g @FiSH-Key Key for %target on $fish10.network
  echo -g @FiSH-Key %key
  window -a @FiSH-Key
}

alias FiSH.removekey {
  var %target = $fish10.context($1)
  if (!$fish10.target.valid(%target)) || (!$fish10.ready) return
  .dll %FiSH_dll FiSH_DelKey10 $fish10.network %target
  if (!$fish10.contact.key(%target)) {
    if ($window(@FiSH-Key)) window -c @FiSH-Key
    echo -a FiSH 10 has no key for %target $+ .
  }
  else echo -a FiSH 10 could not remove the key for %target $+ .
}

alias FiSH.usechankey {
  var %target = $fish10.context($1)
  var %source = $fish10.context($2)
  if ($2 == $null) || (!$fish10.target.valid(%target)) || (!$fish10.target.valid(%source)) {
    echo -a Usage $+ $chr(58) /FiSH.usechankey <target> <source>
    return
  }
  if (!$fish10.ready) return
  var %result = $dll(%FiSH_dll,FiSH_WriteAlias10,$fish10.network %target %source)
  if (%result == ok) echo -a FiSH 10 linked the key for %target to %source $+ .
  elseif (%result == no_key) echo -a FiSH 10 could not find a key for %source $+ .
  else echo -a FiSH 10 could not link %target to %source $+ .
}

alias -l fish10.plain.prefix {
  var %prefix = $readini(%blow_ini,n,FiSH,plain_prefix)
  if (%prefix == $null) return $+(+p,$chr(32))
  return $noqt(%prefix)
}

alias FiSH.prefix {
  if (!$hget(reefcrypt.fish.runtime,initialized)) return
  if ($1 == $null) {
    echo -a FiSH 10 plaintext prefix is $qt($fish10.plain.prefix) $+ .
    return
  }
  ; Quote the value so Windows' INI API preserves the trailing separator.
  writeini -n $qt(%blow_ini) FiSH plain_prefix $qt($noqt($1-) $+ $chr(32))
}

alias FiSH.showmyip {
  if (!$hget(reefcrypt.fish.runtime,initialized)) return
  var %public.ip = $dll(%FiSH_dll,FiSH_GetMyIP,$null)
  if (%public.ip != $null) echo -a FiSH 10 public IP $+ $chr(58) %public.ip
  else echo -a FiSH 10 could not look up the public IP. Check MyIP_service in blow.ini.
}

alias -l fish10.enabled {
  return $iif($remove($1,$chr(91),$chr(93)) == On,$true,$false)
}

on *:CONNECT:{
  if ($fish10.enabled(%autoset_localip)) && ($hget(reefcrypt.fish.runtime,initialized)) {
    var %public.ip = $dll(%FiSH_dll,FiSH_GetMyIP,$null)
    if (%public.ip != $null) localinfo $iif($host != $null,$host,%public.ip) %public.ip
  }
}

alias -l fish10.pending.item {
  return $+($cid,:,$sha256($lower($1)))
}

alias -l fish10.cbc.offer {
  return $dll(%FiSH_dll,INI_GetSectionBool,$fish10.network $1 dh1080_cbc 1)
}

alias -l fish10.dh.public.valid {
  if ($len($1) == 181) && ($right($1,1) !== A) return $false
  if ($len($1) != 180) && ($len($1) != 181) return $false
  return $iif($regex($1,/^[A-Za-z0-9+\/]+$/),$true,$false)
}

alias -l fish10.dh.peer.valid {
  if (($1 == $me) || ($1 == $null) || ($left($1,1) isin $gettok($chantypes,2,61))) return $false
  return $iif($regex($1,/^[^!@=+%~#&$:\x2c*?\x00-\x20\x7f]+$/),$true,$false)
}

alias keyx FiSH.DH1080_INIT $1

alias FiSH.DH1080_INIT {
  var %peer = $fish10.context($1)
  if ($status != connected) || (!$fish10.dh.peer.valid(%peer)) {
    echo -a Usage $+ $chr(58) /keyx <nick> or /keyx in a connected query
    return
  }
  if (!$fish10.ready) return
  var %item = $fish10.pending.item(%peer)
  if ($hget(reefcrypt.fish.pending,%item)) {
    echo -a FiSH 10 already has an exchange pending with %peer $+ .
    return
  }
  var %pair = $dll(%FiSH_dll,DH1080_gen,$null)
  if (!$fish10.dh.public.valid($gettok(%pair,2,32))) {
    echo -a FiSH 10 could not generate a DH1080 key pair.
    return
  }
  var %cbc = $fish10.cbc.offer(%peer)
  ; Pending private keys live for 120 seconds in memory and are never written to disk.
  hadd -mu120 reefcrypt.fish.pending %item $gettok(%pair,1,32) %cbc
  .notice %peer DH1080_INIT $gettok(%pair,2,32) $iif(%cbc == 1,CBC)
  echo -a FiSH 10 started a key exchange with %peer $+ .
}

on ^*:NOTICE:DH1080_*:?:{
  if (($1 !== DH1080_INIT) && ($1 !== DH1080_FINISH)) return
  if (!$regex($parms,/^DH1080_(?:INIT|FINISH) [A-Za-z0-9+\/]+(?: CBC)?\z/)) return
  if (!$fish10.dh.public.valid($2)) || (!$fish10.dh.peer.valid($nick)) return
  if (!$hget(reefcrypt.fish.runtime,initialized)) || ($fish10.network == $null) return
  haltdef
  fish10.dh.receive $nick $1 $2 $iif($3 === CBC,1,0)
}

alias -l fish10.dh.receive {
  var %item = $fish10.pending.item($1)
  var %pending = $hget(reefcrypt.fish.pending,%item)
  if ($2 === DH1080_FINISH) {
    if (%pending == $null) return
    if ($4 == 1) && ($gettok(%pending,2,32) != 1) return
    var %private = $gettok(%pending,1,32)
  }
  else {
    ; If both peers initiated, the attempt from the first sorted nick wins.
    if (%pending != $null) && ($gettok($sorttok($me $1,32),1,32) == $me) return
    var %pair = $dll(%FiSH_dll,DH1080_gen,$null)
    var %private = $gettok(%pair,1,32), %public = $gettok(%pair,2,32)
    if (!$fish10.dh.public.valid(%public)) return
  }
  var %secret = $dll(%FiSH_dll,DH1080_comp,%private $3)
  if (%secret == $null) return
  var %key = $iif($4 == 1,cbc:) $+ %secret
  if ($dll(%FiSH_dll,FiSH_WriteKey10,raw_bytes $fish10.network $1 %key) != ok) return
  if (%pending != $null) hdel reefcrypt.fish.pending %item
  if ($2 === DH1080_INIT) .notice $1 DH1080_FINISH %public $iif($4 == 1,CBC)
  echo -a FiSH 10 established an $iif($4 == 1,CBC,ECB) key with $1 $+ .
}

on *:OPEN:?:*:{
  if (!$fish10.enabled(%autokeyx)) || (!$hget(reefcrypt.fish.runtime,initialized)) return
  if ($fish10.network == $null) || (!$fish10.dh.peer.valid($target)) return
  if (!$fish10.contact.key($target)) FiSH.DH1080_INIT $target
}

on ^*:NICK:{
  if (!$fish10.enabled(%NickTrack)) || (!$hget(reefcrypt.fish.runtime,initialized)) return
  if (($fish10.network == $null) || (!$query($nick))) return
  .dll %FiSH_dll FiSH_WriteAlias10 $fish10.network $newnick $nick nick
}

; The optional outgoing marker changes the local echo only. A quiet /msg still
; passes through the DLL's normal outgoing encryption hook.
on *:INPUT:*:{
  if (!$fish10.enabled(%mark_outgoing)) || ($status != connected) || ($1 == $null) return
  if ($left($1,1) == $comchar) || ($ctrlenter) || ($inpaste) return
  if (($chan($target) == $null) && ($query($target) == $null)) return
  if (!$hget(reefcrypt.fish.runtime,initialized)) || ($fish10.network == $null) return
  if (!$dll(%FiSH_dll,INI_GetBool,process_outgoing 1)) || (!$fish10.contact.key($target)) return
  var %prefix = $fish10.plain.prefix
  if (%prefix != $null) && ($left($parms,$len(%prefix)) === %prefix) return
  var %mark = $fish10.marker
  var %shown.nick = $+($chr(60),$me,$chr(62))
  var %shown.text = $parms
  if (%mark_style == 1) %shown.text = %shown.text %mark
  elseif (%mark_style == 3) %shown.nick = $+($chr(60),$chr(2),$me,$chr(2),$chr(62))
  else %shown.text = %mark %shown.text
  .msg $target $parms
  echo -tirm $target %shown.nick %shown.text
  halt
}

alias -l fish10.marker {
  var %mark = $noqt($readini(%blow_ini,n,FiSH,mark_encrypted))
  ; Expand the documented marker syntax without evaluating arbitrary INI text.
  while ($regex(%mark,/\$chr\(([0-9]+)\)/i)) {
    var %char = $regml(1)
    var %start = $calc($regml(1).pos - 5)
    var %end = $calc($regml(1).pos + $len(%char) + 1)
    var %replacement = $null
    if (%char isnum 1-65535) %replacement = $chr(%char)
    var %mark = $left(%mark,$calc(%start - 1)) $+ %replacement $+ $mid(%mark,%end)
  }
  var %mark = $replace(%mark,$+($chr(36),$chr(43)),$null)
  var %mark = $regsubex(%mark,/^\x20+|\x20+$/g,$null)
  return $iif(%mark != $null,%mark,$chr(183))
}

alias -l fish10.debug.line {
  echo -s FiSH 10 $1-
  if ($1- != $null) aline @FiSH-Debug FiSH 10 $1-
}

alias fishdebug {
  if (!$window(@FiSH-Debug)) window -h @FiSH-Debug
  clear @FiSH-Debug
  fish10.debug.line mIRC $version on Windows $os
  fish10.debug.line Startup initialized $iif($hget(reefcrypt.fish.runtime,initialized),yes,no)
  fish10.debug.line Configuration %blow_ini
  fish10.debug.line Engine %FiSH_dll
  fish10.debug.line Injector $+($nofile($mircexe),fish_inject.dll)
  fish10.debug.line SSL ready $sslready
  fish10.debug.line SSL mode $readini($mircini,n,ssl,load)
  fish10.debug.line SSL version $sslversion
  fish10.debug.line Connection $status $fish10.network SSL $ssl
  if ($hget(reefcrypt.fish.runtime,initialized)) {
    fish10.debug.line $dll(%FiSH_dll,FiSH_GetVersion,$null)
    fish10.debug.line $dll($qt($nofile($mircexe) $+ fish_inject.dll),FiSH_GetInjectVersion,$null)
    .dll %FiSH_dll NetworkDebugInfo
    .dll $qt($nofile($mircexe) $+ fish_inject.dll) InjectDebugInfo
  }
  if ($1 == copy) {
    clipboard -n $line(@FiSH-Debug,1)
    var %i = 2
    while (%i <= $line(@FiSH-Debug,0)) {
      clipboard -an $line(@FiSH-Debug,%i)
      inc %i
    }
  }
  window -c @FiSH-Debug
}

alias -l fish10.menu.target {
  if ($menu == nicklist) return $1
  if ($menu == channel) return $chan
  if ($menu == query) return $fish10.context($1)
}

alias -l fish10.menu.setkey {
  if (!$fish10.target.valid($1)) return
  var %key = $input(Enter a key. Use cbc: at the beginning for CBC.,ep,$active,FiSH 10)
  if (%key != $null) FiSH.setkey_utf8 $1 %key
}

alias -l fish10.menu.alias {
  if (!$fish10.target.valid($1)) return
  var %source = $input(Use the key from which channel or nick?,e,$active,FiSH 10)
  if (%source != $null) FiSH.usechankey $1 %source
}

alias -l fish10.menu.prefix {
  var %prefix = $input(Enter the plaintext prefix.,e,$active,FiSH 10,$regsubex($fish10.plain.prefix,/\x20+$/,$null))
  if (%prefix != $null) FiSH.prefix %prefix
}

alias -l fish10.menu.prefix.off {
  if ($hget(reefcrypt.fish.runtime,initialized)) writeini -n $qt(%blow_ini) FiSH plain_prefix $qt($null)
}

alias -l fish10.menu.marker {
  var %mark = $input(Enter a marker for encrypted messages.,e,$active,FiSH 10,$noqt($readini(%blow_ini,n,FiSH,mark_encrypted)))
  if (%mark != $null) writeini -n $qt(%blow_ini) FiSH mark_encrypted $qt(%mark)
}

alias -l fish10.option.toggle {
  if (!$hget(reefcrypt.fish.runtime,initialized)) return
  var %current = $dll(%FiSH_dll,INI_GetBool,$1 $2)
  .dll %FiSH_dll INI_SetBool $1 $iif(%current == 1,0,1)
}

alias -l fish10.contact.toggle {
  if (!$fish10.target.valid($1)) || (!$fish10.ready) return
  var %current = $dll(%FiSH_dll,INI_GetSectionBool,$fish10.network $1 $2 $3)
  .dll %FiSH_dll INI_SetSectionBool $fish10.network $1 $2 $iif(%current == 1,0,1)
}

menu status,channel,query,nicklist {
  FiSH 10
  .$iif($fish10.menu.target($1),Set a key):fish10.menu.setkey $fish10.menu.target($1)
  .$iif($fish10.menu.target($1),Show the key):FiSH.showkey $fish10.menu.target($1)
  .$iif($fish10.menu.target($1),Remove the key):FiSH.removekey $fish10.menu.target($1)
  .$iif($fish10.menu.target($1),Use another contact's key):fish10.menu.alias $fish10.menu.target($1)
  .$iif($fish10.dh.peer.valid($fish10.menu.target($1)),Start key exchange):keyx $fish10.menu.target($1)
  .$iif($fish10.dh.peer.valid($fish10.menu.target($1)),Toggle CBC offer):fish10.contact.toggle $fish10.menu.target($1) dh1080_cbc 1
  .$iif($menu == channel,Toggle topic encryption):fish10.contact.toggle $fish10.menu.target($1) encrypt_topic 0
  .$iif($fish10.menu.target($1),Toggle incoming marker for this contact):fish10.contact.toggle $fish10.menu.target($1) mark_encrypted $iif($readini(%blow_ini,n,FiSH,mark_encrypted),1,0)
  .Preferences
  ..Toggle incoming decryption:fish10.option.toggle process_incoming 1
  ..Toggle outgoing encryption:fish10.option.toggle process_outgoing 1
  ..Toggle action encryption:fish10.option.toggle encrypt_action 0
  ..Toggle notice encryption:fish10.option.toggle encrypt_notice 0
  ..Toggle automatic key exchange:set %autokeyx $iif($fish10.enabled(%autokeyx),Off,On)
  ..Toggle nick tracking:set %NickTrack $iif($fish10.enabled(%NickTrack),Off,On)
  ..Toggle automatic public IP:set %autoset_localip $iif($fish10.enabled(%autoset_localip),Off,On)
  ..Set plaintext prefix:fish10.menu.prefix
  ..Disable plaintext prefix:fish10.menu.prefix.off
  ..Set encryption marker:fish10.menu.marker
  ..Incoming marker
  ...After message:writeini -n $qt(%blow_ini) FiSH mark_position 1
  ...Before message:writeini -n $qt(%blow_ini) FiSH mark_position 2
  ...Off:writeini -n $qt(%blow_ini) FiSH mark_position 0
  ..Outgoing marker
  ...After message:set %mark_outgoing On | set %mark_style 1
  ...Before message:set %mark_outgoing On | set %mark_style 2
  ...Bold nickname:set %mark_outgoing On | set %mark_style 3
  ...Off:set %mark_outgoing Off
  .Show public IP:FiSH.showmyip
  .Open blow.ini:run $qt(%blow_ini)
  .Show diagnostics:fishdebug
  .Copy diagnostics:fishdebug copy
}
