#include "fish-internal.h"
#include "fish-inject-engine.h"
#include "mircdll.h"
#include "aead.h"
#include <atomic>
#include <thread>

static CRITICAL_SECTION s_iniLock;

static std::shared_ptr<CBlowIni> GetBlowIni()
{
	static std::shared_ptr<CBlowIni> ls_instance;

	if(!ls_instance)
	{
		::EnterCriticalSection(&s_iniLock);
		// the lock makes sure we only ever get one CBlowIni instance.
		if(!ls_instance) ls_instance = std::make_shared<CBlowIni>();
		::LeaveCriticalSection(&s_iniLock);
	}

	return ls_instance;
}


std::map<HANDLE, std::string> s_socketMap;
static CRITICAL_SECTION s_socketMapLock;
static DWORD s_maxMircReturnBytes = MIRC_PARAM_DATA_LENGTH_LOW;
static std::atomic<const char*> s_aeadError{nullptr};
static std::atomic<bool> s_engineRegistered{false};


static std::string SocketNetwork(HANDLE a_socket)
{
	::EnterCriticalSection(&s_socketMapLock);
	const auto l_network = s_socketMap.find(a_socket);
	const std::string l_name = l_network != s_socketMap.end() ? l_network->second : std::string();
	::LeaveCriticalSection(&s_socketMapLock);
	return l_name;
}


static std::string AeadNetworkName(const std::string& a_network)
{
	// mIRC filters the NETWORK token before exposing it to scripts as $network.
	std::string l_name;
	for(char l_char : a_network)
	{
		if((l_char >= 'A' && l_char <= 'Z') || (l_char >= 'a' && l_char <= 'z')
			|| (l_char >= '0' && l_char <= '9') || l_char == '_' || l_char == '.' || l_char == '-')
			l_name += l_char;
	}
	return l_name;
}


static std::string_view WithoutIrcTerminator(std::string_view a_line)
{
	if(a_line.ends_with('\n'))
		a_line.remove_suffix(1);
	if(a_line.ends_with('\r'))
		a_line.remove_suffix(1);
	return a_line;
}


static char* CopyIrcLine(std::string_view a_line)
{
	char* l_result = new char[a_line.size() + 1];
	if(!a_line.empty())
		memcpy(l_result, a_line.data(), a_line.size());
	l_result[a_line.size()] = '\0';
	return l_result;
}


static char* DropAeadMessage(const char* a_reason)
{
	s_aeadError.store(a_reason);
	// A non-null, empty replacement consumes the original outgoing IRC line.
	return CopyIrcLine({});
}


/* called from fish_inject.dll */
char* _OnIncomingIRCLine(HANDLE a_socket, const char* a_line, size_t a_len)
{
	if (!a_socket || !a_line || a_len < 1 || (*a_line != ':' && *a_line != '@'))
		return nullptr;

	// handle message tags:
	// ( http://ircv3.atheme.org/specification/message-tags-3.2 )
	bool l_hasTag = (*a_line == '@');
	const char *l_afterTag = a_line;

	if (l_hasTag)
	{
		const char *p = strstr(a_line, " :");

		if (!p)
			return nullptr;

		l_afterTag = p + 1;
	}

	if (strstr(l_afterTag, " ") == strstr(l_afterTag, " 005 "))
	{
		const std::string l_line(a_line, a_len);
		std::string::size_type l_pos = l_line.find(" NETWORK=");

		/*
		  TODO: Use this as a trigger to initiate SendMsg to mirc.exe after sufficient delay
		  to request value of $network. Alternative is an export function to feed the
		  $network string to the DLL.
		  mIRC sets $network string by removing characters outside this list: a-z A-Z 0-9 _ . -
		  When $network does not match the NETWORK=string, the input to FiSH_WriteKey10 and
		  FiSH_GetKey10 is different than the string used by encryption and decryption looking
		  for the channel key. In rare cases MIRC gets $network from the servers list GROUP string
		  or from the server's welcome message
*/

		if(l_pos != std::string::npos)
		{
			l_pos += 9; // strlen(" NETWORK=")
			std::string::size_type l_endPos = l_line.find(" ", l_pos);
			if(l_endPos == std::string::npos) l_endPos = l_line.size();

			::EnterCriticalSection(&s_socketMapLock);
			// allow overwriting network names for dis/re-connecting BNCs and such:
			s_socketMap[a_socket] = l_line.substr(l_pos, l_endPos - l_pos);
			::LeaveCriticalSection(&s_socketMapLock);

			return nullptr;
		}
	}

	// quick exit to save some CPU cycles:
	if(!strstr(a_line, "+OK ") && !strstr(a_line, "mcps ")
		&& !strstr(a_line, fish_aead::Marker.data()))
		return nullptr;

	const auto l_ini = GetBlowIni();

	if(!l_ini->GetBool(L"process_incoming", true))
		return nullptr;

	/** list of stuff we possibly need to decrypt: **
		:nick!ident@host PRIVMSG #chan :+OK 2T5zD0mPgMn
		:nick!ident@host PRIVMSG #chan :\x01ACTION +OK 2T5zD0mPgMn\x01
		:nick!ident@host PRIVMSG ownNick :+OK 2T5zD0mPgMn
		:nick!ident@host PRIVMSG ownNick :\x01ACTION +OK 2T5zD0mPgMn\x01
		:nick!ident@host NOTICE ownNick :+OK 2T5zD0mPgMn
		:nick!ident@host NOTICE #chan :+OK 2T5zD0mPgMn
		TODO: support encrypting outbound notices to the next 5 targets @#chan +#chan %#chan &#chan ~#chan
		:nick!ident@host NOTICE @#chan :+OK 2T5zD0mPgMn
		:nick!ident@host NOTICE ~#chan :+OK 2T5zD0mPgMn
		:nick!ident@host NOTICE %#chan :+OK 2T5zD0mPgMn
		:nick!ident@host NOTICE +#chan :+OK 2T5zD0mPgMn
		  if '&' is within STATUSMSG=~&@%+ then &#chan is a group target not the name of a server-local channel
		:nick!ident@host NOTICE &#chan :+OK 2T5zD0mPgMn
		(topic) :irc.tld 332 nick #chan :+OK hqnSD1kaIaE00uei/.3LjAO1Den3t/iMNsc1
		:nick!ident@host TOPIC #chan :+OK JRFEAKWS
		(topic /list) :irc.tld 322 nick #chan 2 :[+snt] +OK BLAH
		@aaa=bbb;ccc;example.com/ddd=eee :nick!ident@host.com PRIVMSG me :Hello
	*/

	// back up message tag, then process without it:
	std::string l_tag;
	std::string l_line;

	if (l_hasTag)
	{
		l_tag = std::string(a_line, static_cast<size_t>(l_afterTag - a_line));
		l_line = std::string(l_afterTag, a_len - l_tag.size());
	}
	else
	{
		l_line = std::string(a_line, a_len);
	}

	std::string l_cmd, l_contact, l_message, l_ircTarget;
	std::string::size_type l_cmdPos, l_tmpPos, l_msgPos;

	StrTrimRight(l_line);

	l_cmdPos = l_line.find(' ');
	if(l_cmdPos != std::string::npos)
	{
		while(l_line[l_cmdPos] == ' ') l_cmdPos++;
		l_tmpPos = l_line.find(' ', l_cmdPos);

		if(l_tmpPos != std::string::npos)
		{
			while(l_line[l_tmpPos + 1] == ' ') l_tmpPos++;
			l_cmd = l_line.substr(l_cmdPos, l_tmpPos - l_cmdPos);

			l_msgPos = l_line.find(" :", l_tmpPos + 1);

			if(l_msgPos != std::string::npos)
			{
				l_msgPos += 2;
				l_message = l_line.substr(l_msgPos);
			}
		}
	}

	if(l_cmd.empty() || l_message.empty())
		return nullptr;

	// check if +OK is in the message part of the line:
	if(l_message.find("+OK ") == std::string::npos && l_message.find("mcps ") == std::string::npos
		&& !l_message.starts_with(fish_aead::Marker))
		return nullptr;

	enum {
		CMD_PRIVMSG = 1,
		CMD_ACTION,
		CMD_NOTICE,
		CMD_N332, // 332 channel :topic
		CMD_TOPIC,
		CMD_N322 // 322 channel users :topic
	} l_cmd_type;

	if(!_stricmp(l_cmd.c_str(), "PRIVMSG"))
		l_cmd_type = CMD_PRIVMSG;
	else if(!_stricmp(l_cmd.c_str(), "NOTICE"))
		l_cmd_type = CMD_NOTICE;
	else if(!strcmp(l_cmd.c_str(), "332"))
		l_cmd_type = CMD_N332;
	else if(!_stricmp(l_cmd.c_str(), "TOPIC"))
		l_cmd_type = CMD_TOPIC;
	else if(!strcmp(l_cmd.c_str(), "322"))
		l_cmd_type = CMD_N322;
	else
		return nullptr;

	std::string l_leading, l_trailing;

	if(l_cmd_type == CMD_N322 || l_cmd_type == CMD_N332 || l_cmd_type == CMD_TOPIC)
	{
		// TOPIC names the channel first; the numeric replies name the recipient first.
		size_t l_targetPos = l_tmpPos + 1;
		if (l_cmd_type != CMD_TOPIC)
		{
			const size_t l_recipientEnd = l_line.find(' ', l_targetPos);
			l_targetPos = l_line.find_first_not_of(' ', l_recipientEnd);
		}
		if (l_targetPos >= l_msgPos - 2)
			return nullptr;
		const size_t l_targetEnd = l_line.find(' ', l_targetPos);
		l_contact = l_line.substr(l_targetPos, l_targetEnd - l_targetPos);

		if(l_cmd_type == CMD_N322 && !l_message.empty())
		{
			// account for channel modes in /list, like "[+nts] +OK BLAH"
			if(l_message[0] == '[')
			{
				l_tmpPos = l_message.find("] +OK ");

				if(l_tmpPos != std::string::npos)
				{
					l_leading = l_message.substr(0, l_tmpPos + 2);
					l_message.erase(0, l_tmpPos + 2);
				}
			}
		}
	}
	else
	{
		bool l_psyLogHack = false;

		l_ircTarget = l_line.substr(l_tmpPos + 1, l_msgPos - 2 - l_tmpPos - 1);
		l_contact = l_ircTarget;

		if(l_cmd_type == CMD_PRIVMSG && l_line.compare(0, 16, ":-psyBNC!psyBNC@") == 0)
		{
			// psyBNC private message log playback hack
			// example <-psyBNC> Thu Dec 27 20:52:38 :(nick!ident@host) +OK blowcryptedtext
			// example 2: <-psyBNC> lk~Thu Nov 29 00:01:43 :(nick!ident@host) +OK blowcryptedtext
			// example 3: <-psyBNC> ef'Thu Nov 29 00:01:43 :(nick!ident@host) +OK blowcryptedtext

			l_tmpPos = l_message.find(" :(");

			if(l_tmpPos == std::string::npos || l_tmpPos == 0)
				return nullptr;

			std::string::size_type l_endPos = l_message.find(") ", l_tmpPos + 3);

			if(l_endPos == std::string::npos)
				return nullptr;

			l_contact = l_message.substr(l_tmpPos + 3, l_endPos - l_tmpPos - 3);
			std::string l_timestamp = l_message.substr(0, l_tmpPos);

			l_tmpPos = l_timestamp.find_first_of("~'");

			if(l_tmpPos != std::string::npos)
			{
				// move network prefix to nick.... :oh god why:
				l_contact = l_timestamp.substr(0, l_tmpPos + 1) + l_contact;
				l_timestamp.erase(0, l_tmpPos + 1);
			}

			l_leading = "[" + l_timestamp + "] <" + l_contact + "> ";
			l_message.erase(0, l_endPos + 2);

			// this *must* be a query message, so split off nick (in order to find the key later):
			l_tmpPos = l_contact.find('!');
			l_contact = (l_tmpPos != std::string::npos ? l_contact.substr(0, l_tmpPos) : "");

			l_psyLogHack = true;
		}

		if(!l_contact.empty() && !l_psyLogHack)
		{
			switch(l_contact[0])
			{
			case '&': // this assumes seeing notice to &#chan is group notice to protected ops +a
				// in #chan vs notice sent to entire server-local channel named literal &#something
				// best practice will be to add code to inspect 005 for STATUSMSG=~&@%+
				// in the absence of that check, likelihood of group notice to &'s is higher
				// than local chan named &#something
				if (l_contact[1] == '#') goto group_notice_to_protected_ops;
			case '#':
				// channel, l_contact = channel name, all is fine.
				break;
			case '@':
			case '+':
			case '%':
			case '~': 	// receive notice to group target ~#chan
				// networks like Rizon permit giving ~ status even to un-identified nick(s)
			group_notice_to_protected_ops:
				// onotice or something like that.
				l_contact.erase(0, 1);
				// left in l_contact is the channel name.
				break;
			default:
				// probably a query message. Need to make l_contact the nick name:
				{
					l_tmpPos = l_line.find('!');

					if(l_tmpPos != std::string::npos)
					{
						l_contact = l_line.substr(1, l_tmpPos - 1);
					}
					else
					{
						l_contact.clear();
					}
				}
				// :TODO: for future versions: keep track of local nickname and use that to determine channel/query.
			}
		}
	}

	if(l_contact.empty())
		return nullptr;

	const std::string l_networkName = SocketNetwork(a_socket);
	if(l_cmd_type == CMD_PRIVMSG)
	{
		const std::string l_network = AeadNetworkName(l_networkName);
		const bool l_explicitChannel = l_ircTarget.starts_with('#') || l_ircTarget.starts_with('&');
		std::string l_aeadKey = l_explicitChannel ? l_ini->GetAeadKey(l_network, l_ircTarget) : std::string();
		if(l_aeadKey.empty())
			l_aeadKey = l_ini->GetAeadKey(l_network, l_contact);
		if(l_message.starts_with(fish_aead::Marker))
		{
			const size_t l_payload = l_tag.size() + l_msgPos;
			const auto l_frame = WithoutIrcTerminator(std::string_view(a_line + l_payload, a_len - l_payload));
			fish_aead::Key l_key{};
			std::string l_plaintext;
			if(!l_leading.empty() || l_line.size() + 2 > 512
				|| !fish_aead::ParseKey(l_aeadKey, l_key) || !fish_aead::Open(l_key, l_frame, l_plaintext)
				|| l_plaintext.front() == 0x01)
				return nullptr;
			return CopyIrcLine(l_tag + l_line.substr(0, l_msgPos) + l_plaintext + "\n");
		}
		if(!l_aeadKey.empty() || l_ini->HasAeadKeyForTarget(l_contact)
			|| (l_explicitChannel && l_ircTarget != l_contact && l_ini->HasAeadKeyForTarget(l_ircTarget)))
			return nullptr; // Keep legacy ciphertext opaque in an AEAD conversation.
	}

	if(l_cmd_type == CMD_PRIVMSG && l_message.find("\x01""ACTION ") == 0)
	{
		l_message.erase(0, 8);
		if(l_message.size() > 0 && l_message[l_message.size() - 1] == 0x01) l_message.erase(l_message.size() - 1);
		l_cmd_type = CMD_ACTION;
	}

	if(l_message.find("+OK ") == 0)
		l_message.erase(0, 4);
	else if(l_message.find("mcps ") == 0)
		l_message.erase(0, 5);
	else
		return nullptr; // something must have gone awry.

	// account for stuff like trailing time stamps from BNCs:
	if((l_tmpPos = l_message.find(' ')) != std::string::npos)
	{
		l_trailing = l_message.substr(l_tmpPos);
		l_message.erase(l_tmpPos);
	}

	// get blowfish key...
	bool l_cbc;

	std::string l_blowKey = l_ini->GetBlowKey(l_networkName, l_contact, l_cbc);

	if(l_blowKey.empty())
		return nullptr;

	// put together new message:
	std::string l_newMsg;

	const bool l_messageCbc = !l_message.empty() && l_message[0] == '*';
	if(l_messageCbc != l_cbc && l_ini->GetBool(L"strict_cipher_mode", false))
		return nullptr;
	l_cbc = l_messageCbc;
	if(l_cbc)
		l_message.erase(0, 1);
	const size_t l_maxLength = l_ini->MaxKeyLength(l_cbc);
	if(l_blowKey.size() > l_maxLength)
		l_blowKey.resize(l_maxLength);

	int l_decryptionResult = blowfish_decrypt_auto(l_cbc, l_message, l_newMsg, l_blowKey);

	if(l_decryptionResult == 0)
	{
		// compatibility fix
		// (we only encode the actual MSG part of CTCP ACTIONs, but the old FiSH.dll and some scripts etc.
		// encode the whole thing including \x01 and so on)
		if(l_cmd_type == CMD_PRIVMSG && l_newMsg.compare(0, 8, "\x01""ACTION ") == 0)
		{
			l_newMsg.erase(0, 8);
			if(l_newMsg.size() > 0 && l_newMsg[l_newMsg.size() - 1] == 0x01) l_newMsg.erase(l_newMsg.size() - 1);
			l_cmd_type = CMD_ACTION;
		}
		// this obviously needs to be done before appending the crypt mark... fixed 2011-11.
	}

	switch(l_decryptionResult)
	{
	case -1:
		l_newMsg = l_message + "=[FiSH: DECRYPTION FAILED!]=";
		break;
	case 1:
		l_newMsg += "\x02&\x02";
		 /* fall through */
	case 0:
		l_newMsg += l_trailing;
		if(l_ini->GetSectionBool(l_networkName, l_contact, L"mark_encrypted", !l_ini->GetStringW(L"mark_encrypted", L"").empty()))
		{ // try local setting and use global setting as default ^^
			int l_markPos = l_ini->GetInt(L"mark_position"); // 1 = append, 2 = prepend, 0 = disabled
			if(l_markPos > 0 && l_markPos <= 2)
			{
				const std::wstring l_markWide = l_ini->GetStringW(L"mark_encrypted");
				std::string l_mark;

				if(l_ini->NoLegacy())
				{
					std::string l_markDumb;
					// if the .ini file is UTF-8 encoded, UnicodeToCp would double-encode
					// the characters, so try this dumbfolded approach of conversion.

					for (const wchar_t ch : l_markWide)
					{
						if(ch && ch <= std::numeric_limits<unsigned char>::max()) l_markDumb += (unsigned char)ch;
					}

					if(l_markDumb.empty() || !Utf8Validate(l_markDumb.c_str()))
					{
						l_mark = UnicodeToCp(CP_UTF8, l_markWide);
					}
					else
					{
						l_mark = l_markDumb;
					}
				}
				else
				{
					l_mark = UnicodeToCp(CP_UTF8, l_markWide);
				}

				l_mark = SimpleMIRCParser(l_mark);

				if(l_markPos == 1)
					l_newMsg.append(l_mark);
				else
					l_newMsg.insert(0, l_mark);
			}
		}
		break;
	}

	// form new line:
	l_newMsg = l_tag + l_line.substr(0, l_msgPos) +
		(l_cmd_type == CMD_ACTION ? "\x01""ACTION " : "") +
		l_leading + l_newMsg +
		(l_cmd_type == CMD_ACTION ? "\x01\n" : "\n");

	// return and let fish_inject handle the rest:
	char* szResult = new char[l_newMsg.size() + 1];
	strcpy_s(szResult, l_newMsg.size() + 1, l_newMsg.c_str());

	return szResult;
}


static std::string_view AeadTarget(std::string_view a_target)
{
	const auto l_prefixEnd = a_target.find_first_not_of("~@%+");
	if(l_prefixEnd == std::string_view::npos)
		return a_target;
	a_target.remove_prefix(l_prefixEnd);
	if(a_target.starts_with("&#") || a_target.starts_with("&&"))
		a_target.remove_prefix(1);
	if(!a_target.starts_with('#') && !a_target.starts_with('&'))
		a_target = a_target.substr(0, a_target.find_first_of("!@%"));
	return a_target;
}


static char* OnOutgoingAead(HANDLE a_socket, std::string_view a_line, const CBlowIni& a_ini)
{
	const auto l_line = WithoutIrcTerminator(a_line);
	size_t l_cmdStart = 0;
	if(l_line.starts_with('@'))
		l_cmdStart = l_line.find_first_not_of(' ', l_line.find(' '));
	if(l_cmdStart == std::string_view::npos)
		return nullptr;
	const size_t l_cmdEnd = l_line.find(' ', l_cmdStart);
	if(l_cmdEnd == std::string_view::npos)
		return nullptr;
	const auto l_cmd = l_line.substr(l_cmdStart, l_cmdEnd - l_cmdStart);
	const bool l_privmsg = l_cmd.size() == 7 && !_strnicmp(l_cmd.data(), "PRIVMSG", 7);
	if(!l_privmsg && !(l_cmd.size() == 8 && !_strnicmp(l_cmd.data(), "CPRIVMSG", 8)))
		return nullptr;
	const size_t l_targetStart = l_line.find_first_not_of(' ', l_cmdEnd);
	if(l_targetStart == std::string_view::npos)
		return nullptr;
	const size_t l_targetEnd = l_line.find(' ', l_targetStart);
	const auto l_targets = l_line.substr(l_targetStart, l_targetEnd - l_targetStart);

	const std::string l_network = AeadNetworkName(SocketNetwork(a_socket));
	std::string l_keyHex;
	size_t l_start = 0;
	// Normally the socket layer has already split multi-target PRIVMSG lines.
	// If it could not split this variant, suppress the entire list if any target uses AEAD.
	for(size_t l_comma; l_start <= l_targets.size(); l_start = l_comma + 1)
	{
		l_comma = l_targets.find(',', l_start);
		const auto l_target = l_targets.substr(l_start, l_comma - l_start);
		const auto l_contact = AeadTarget(l_target);
		l_keyHex = a_ini.GetAeadKey(l_network, std::string(l_target));
		if(l_keyHex.empty() && l_contact != l_target)
			l_keyHex = a_ini.GetAeadKey(l_network, std::string(l_contact));
		if(!l_keyHex.empty())
			break;
		// NETWORK is supplied by the server. A mismatched or missing token must
		// not make a known protected target silently switch to a weaker mode.
		if(a_ini.HasAeadKeyForTarget(std::string(l_target))
			|| (l_contact != l_target && a_ini.HasAeadKeyForTarget(std::string(l_contact))))
			return DropAeadMessage("FiSH AEAD: message blocked because the network or target spelling does not match the key.");
		if(l_comma == std::string_view::npos)
			break;
	}
	if(l_keyHex.empty())
		return nullptr;

	if(!a_ini.GetBool(L"process_outgoing", true))
		return DropAeadMessage("FiSH AEAD: message blocked because outgoing encryption is disabled.");
	const size_t l_bodyStart = l_line.find_first_not_of(' ', l_targetEnd);
	if(!l_privmsg || l_targets.find(',') != std::string_view::npos || l_bodyStart == std::string_view::npos)
		return DropAeadMessage("FiSH AEAD: unsupported IRC message format.");
	const bool l_hasColon = l_line[l_bodyStart] == ':';
	const auto l_plaintext = l_line.substr(l_bodyStart + l_hasColon);
	if(l_plaintext.empty() || l_plaintext.front() == 0x01
		|| (!l_hasColon && l_plaintext.find(' ') != std::string_view::npos))
		return DropAeadMessage("FiSH AEAD: unsupported IRC message format.");

	fish_aead::Key l_key{};
	std::string l_frame;
	if(!fish_aead::ParseKey(l_keyHex, l_key) || !fish_aead::Seal(l_key, l_plaintext, l_frame))
		return DropAeadMessage("FiSH AEAD: message could not be encrypted.");

	// Reserve space for the server's :nick!user@host prefix on a relayed line.
	// Message tags have their own IRCv3 budget outside this length.
	constexpr size_t RelayPrefixAllowance = 128;
	if(l_bodyStart - l_cmdStart + 1 + l_frame.size() + 2 + RelayPrefixAllowance > 512)
		return DropAeadMessage("FiSH AEAD: message is too long for an IRC line.");
	return CopyIrcLine(std::string(l_line.substr(0, l_bodyStart)) + ":" + l_frame + "\r\n");
}


/* called from fish_inject.dll */
char* _OnOutgoingIRCLine(HANDLE a_socket, const char* a_line, size_t a_len)
{
	if(!a_socket || !a_line || a_len < 1)
		return nullptr;

	const auto l_ini = GetBlowIni();

	if(char* l_aead = OnOutgoingAead(a_socket, std::string_view(a_line, a_len), *l_ini))
		return l_aead;

	if(!l_ini->GetBool(L"process_outgoing", true))
		return nullptr;

	/** list of messages we possibly need to encrypt: **
		PRIVMSG #chan :lulz
		PRIVMSG #chan :\x01ACTION says hi\x01
		NOTICE test :y hello there
		TOPIC #chan :new topic
		CPRIVMSG xxx #chan :lulz
		CNOTICE xxx #chan :lulz
		@label=dc11f13f11 PRIVMSG #chan :Hello
		TODO: if anyof these 5 chars are in 005's STATUSMSG=~&@%+ string
		STATUSMSG= must be checked to avoid mixup with server local channel names beginning with '&#'
		NOTICE @#chan :hello channel @ops
		NOTICE +#chan :hello channel +voices
		NOTICE %#chan :hello channel %halfops
		NOTICE &#chan :hello channel &protected ops mode +a
		NOTICE ~#chan :hello channel ~founders
		(local channel name of &#chan can be tested at EFnet)
	*/

	// handle message tags:
	// ( http://ircv3.atheme.org/specification/message-tags-3.2 )
	bool l_hasTag = (*a_line == '@');
	const char *l_afterTag = a_line;

	if (l_hasTag)
	{
		const char *p = strstr(a_line, " ");

		if (!p)
			return nullptr;

		l_afterTag = p + 1;
	}

	enum {
		CMD_PRIVMSG = 1,
		CMD_CPRIVMSG,
		CMD_ACTION,
		CMD_NOTICE,
		CMD_CNOTICE,
		CMD_TOPIC,
	} l_cmd_type;

	// figure out type of message...
	if(!_strnicmp(l_afterTag, "PRIVMSG ", 8))
		l_cmd_type = CMD_PRIVMSG;
	else if(!_strnicmp(l_afterTag, "CPRIVMSG ", 9))
		l_cmd_type = CMD_CPRIVMSG;
	else if(!_strnicmp(l_afterTag, "NOTICE ", 7))
		l_cmd_type = CMD_NOTICE;
	else if(!_strnicmp(l_afterTag, "CNOTICE ", 8))
		l_cmd_type = CMD_CNOTICE;
	else if(!_strnicmp(l_afterTag, "TOPIC ", 6))
		l_cmd_type = CMD_TOPIC;
	else
		return nullptr;

	// check notice encryption setting:
	if((l_cmd_type == CMD_NOTICE || l_cmd_type == CMD_CNOTICE) && !l_ini->GetBool(L"encrypt_notice", false))
		return nullptr;

	// back up message tag, then process without it:
	std::string l_tag;
	std::string l_line;

	if (l_hasTag)
	{
		l_tag = std::string(a_line, static_cast<size_t>(l_afterTag - a_line));
		l_line = std::string(l_afterTag, a_len - l_tag.size());
	}
	else
	{
		l_line = std::string(a_line, a_len);
	}

	std::string::size_type l_targetPos = l_line.find(' ');

	if (l_targetPos == std::string::npos)
	{
		return nullptr; // "should never happen"
	}
	else
	{
		l_targetPos += 1;
	}

	std::string::size_type l_msgPos = l_line.find(" :", l_targetPos);

	if(l_msgPos == std::string::npos)
		return nullptr; // "should never happen"

	std::string l_target = l_line.substr(l_targetPos, l_msgPos - l_targetPos);

	if (l_cmd_type == CMD_CPRIVMSG || l_cmd_type == CMD_CNOTICE)
	{
		l_targetPos = l_target.find(' ');

		if (l_targetPos != std::string::npos)
		{
			l_target = l_target.substr(0, l_targetPos);
		}
	}

	std::string l_message = l_line.substr(l_msgPos + 2);

	const std::string l_networkName = SocketNetwork(a_socket);

	// kill trailing whitespace, we'll add back the new line later:
	StrTrimRight(l_message);

	if(l_message.empty())
		return nullptr;

	// check topic encryption setting:
	if(l_cmd_type == CMD_TOPIC && !l_ini->GetSectionBool(l_networkName, l_target, L"encrypt_topic", false))
		return nullptr;

	// don't encrypt DH1080 key exchange:
	if((l_cmd_type == CMD_NOTICE || l_cmd_type == CMD_CNOTICE) && l_message.find("DH") == 0)
		return nullptr;

	// check for CTCPs:
	if(l_message[0] == 0x01)
	{
		if(l_message.compare(0, 8, "\x01""ACTION ") != 0 || !l_ini->GetBool(L"encrypt_action", false))
		{
			return nullptr;
		}
		else
		{
			l_message = l_message.substr(8, l_message.size() - 8 - 1); // strip trailing \x01 too
			l_cmd_type = CMD_ACTION;
		}
	}

	// get blowfish key...
	bool l_cbc;
	std::string l_blowKey = l_ini->GetBlowKey(l_networkName, l_target, l_cbc);

	if(l_blowKey.empty())
		return nullptr;
	const size_t l_maxLength = l_ini->MaxKeyLength(l_cbc);
	if(l_blowKey.size() > l_maxLength)
		l_blowKey.resize(l_maxLength);

	// put together new message:
	std::string l_newMsg;

	// check for plain prefix...
	const std::string l_plainPrefix = l_ini->GetString(L"plain_prefix", L"+p ");
	if(!l_plainPrefix.empty() && l_message.find(l_plainPrefix) == 0)
	{
		l_newMsg = l_tag + l_line.substr(0, l_msgPos + 2) + l_message.substr(l_plainPrefix.size()) + "\n";
	}
	else
	{
		blowfish_encrypt_auto(l_cbc, l_message, l_newMsg, l_blowKey);

		l_newMsg =
			l_tag +
			l_line.substr(0, l_msgPos + 2) +
			(l_cmd_type == CMD_ACTION ? "\x01""ACTION +OK " : "+OK ") +
			std::string(l_cbc ? "*" : "") + l_newMsg +
			(l_cmd_type == CMD_ACTION ? "\x01\n" : "\n");
	}

	char* szResult = new char[l_newMsg.size() + 1];
	strcpy_s(szResult, l_newMsg.size() + 1, l_newMsg.c_str());

	return szResult;
}


/* called from fish_inject.dll */
void _FreeString(const char* a_str)
{
	if(a_str) delete[] a_str;
}


/* called from fish_inject.dll */
void _OnSocketClosed(HANDLE a_socket)
{
	::EnterCriticalSection(&s_socketMapLock);
	s_socketMap.erase(a_socket);
	::LeaveCriticalSection(&s_socketMapLock);
}


/* for use from MSL */
MIRC_DLL_EXPORT(FiSH_SetIniPath)
{
	if(data && *data)
	{
		auto l_ini = GetBlowIni();

		l_ini->SetIniPath(UnicodeFromCp(CP_UTF8, data));

		if(!l_ini->IsWritable())
		{
			strcpy_s(data, s_maxMircReturnBytes, "/echo -a *** FiSH 10 *** WARNING: blow.ini is not writable! FiSH will not function correctly. ***");

			return MIRC_RET_DATA_COMMAND;
		}
	}

	return MIRC_RET_CONTINUE;
}

// in: nothing
// out: "%priv_key %pub_key"
MIRC_DLL_EXPORT(DH1080_gen)
{
	std::string l_privKey, l_pubKey;

	if(DH1080_Generate(l_privKey, l_pubKey))
	{
		const std::string l_tmp = l_privKey + " " + l_pubKey;

		strcpy_s(data, s_maxMircReturnBytes, l_tmp.c_str());

		return MIRC_RET_DATA_RETURN;
	}

	return MIRC_RET_HALT;
}


// in: "%priv_key %pub_key"
// out: shared secret
MIRC_DLL_EXPORT(DH1080_comp)
{
	if(data && *data)
	{
		const string_vector l_data = SplitString(data, " ");

		if(l_data.size() >= 2)
		{
			const std::string l_shared = DH1080_Compute(l_data[0], l_data[1]);

			strcpy_s(data, s_maxMircReturnBytes, l_shared.c_str());

			return MIRC_RET_DATA_RETURN;
		}
	}

	return MIRC_RET_HALT;
}


// Preserve the legacy ANSI representation only when it round-trips exactly.
static bool DecodeKeyToAnsi(std::string& a_key)
{
	const std::wstring l_wide = UnicodeFromCp(CP_UTF8, a_key);
	const std::string l_ansi = UnicodeToCp(CP_ACP, l_wide);
	if(UnicodeToCp(CP_UTF8, UnicodeFromCp(CP_ACP, l_ansi)) != a_key)
		return false;
	a_key = l_ansi;
	return true;
}


MIRC_DLL_EXPORT(FiSH_WriteAeadKey10)
{
	if(!data || !*data)
		return MIRC_RET_HALT;
	const auto l_args = SplitString(data, " ");
	const bool l_success = s_engineRegistered.load() && l_args.size() == 3
		&& GetBlowIni()->SetAeadKey(AeadNetworkName(l_args[0]), l_args[1], l_args[2]);
	strcpy_s(data, s_maxMircReturnBytes, l_success ? "ok" : "error");
	return MIRC_RET_DATA_RETURN;
}


MIRC_DLL_EXPORT(FiSH_DelAeadKey10)
{
	if(!data || !*data)
		return MIRC_RET_HALT;
	const auto l_args = SplitString(data, " ");
	const bool l_success = l_args.size() == 2 && GetBlowIni()->SetAeadKey(AeadNetworkName(l_args[0]), l_args[1], {});
	strcpy_s(data, s_maxMircReturnBytes, l_success ? "ok" : "error");
	return MIRC_RET_DATA_RETURN;
}


MIRC_DLL_EXPORT(FiSH_GetAeadError10)
{
	const char* l_error = s_aeadError.exchange(nullptr);
	if(!data)
		return MIRC_RET_HALT;
	strcpy_s(data, s_maxMircReturnBytes, l_error ? l_error : "");
	return MIRC_RET_DATA_RETURN;
}


MIRC_DLL_EXPORT(FiSH_WriteKey10)
{
	if(data && *data)
	{
		string_vector l_data = SplitString(data, " ", 4);
		/* <decode_utf8|raw_bytes> <network> <contact> <key> */

		if(l_data.size() == 4)
		{
			if(_stricmp(l_data[0].c_str(), "decode_utf8") == 0 && !DecodeKeyToAnsi(l_data[3]))
			{
				strcpy_s(data, s_maxMircReturnBytes, "/echo -ac highlight ERROR: key cannot be represented in the system ANSI code page. Use a UTF-8 key.");
				return MIRC_RET_DATA_COMMAND;
			}

			auto l_ini = GetBlowIni();
			const bool l_cbc = HasCBCPrefix(l_data[3]);
			const size_t l_keyLength = l_data[3].size() - (l_cbc ? 4 : 0);
			const size_t l_maxLength = l_ini->MaxKeyLength(l_cbc);
			if(l_keyLength > l_maxLength)
			{
				sprintf_s(data, s_maxMircReturnBytes, "/echo -ac highlight ERROR: key length exceeds limit of %zu bytes.", l_maxLength);

				return MIRC_RET_DATA_COMMAND;
			}

			if(l_ini->WriteBlowKey(l_data[1], l_data[2], l_data[3]))
			{
				strcpy_s(data, s_maxMircReturnBytes, "ok");

				return MIRC_RET_DATA_RETURN;
			}
		}
	}

	return MIRC_RET_HALT;
}


static const std::string s_hexDigits = "0123456789abcdef";

MIRC_DLL_EXPORT(FiSH_GetKey10)
{
	if(data && *data)
	{
		string_vector l_data = SplitString(data, " ");
		/* <network> <contact> [hex] */

		if(l_data.size() >= 2)
		{
			bool l_cbc;
			auto l_ini = GetBlowIni();
			std::string l_key = l_ini->GetBlowKey(l_data[0], l_data[1], l_cbc);
			const size_t l_maxLength = l_ini->MaxKeyLength(l_cbc);
			if(l_key.size() > l_maxLength)
				l_key.resize(l_maxLength);

			if(l_data.size() >= 3 && _stricmp(l_data[2].c_str(), "hex") == 0)
			{
				std::string l_hex;
				l_hex.reserve(l_key.size() * 2);
				for(unsigned char l_byte : l_key)
				{
					l_hex += s_hexDigits[l_byte >> 4];
					l_hex += s_hexDigits[l_byte & 15];
				}
				l_key.swap(l_hex);
			}
			if(l_cbc && !l_key.empty())
				l_key.insert(0, "cbc:");

			strcpy_s(data, s_maxMircReturnBytes, l_key.c_str());

			return MIRC_RET_DATA_RETURN;
		}
	}

	return MIRC_RET_CONTINUE;
}


MIRC_DLL_EXPORT(FiSH_DelKey10)
{
	if(data && *data)
	{
		string_vector l_data = SplitString(data, " ");
		/* <network> <contact> */

		if(l_data.size() >= 2)
		{
			GetBlowIni()->DeleteBlowKey(l_data[0], l_data[1]);
		}
	}

	return MIRC_RET_CONTINUE;
}


static bool ParseMessageArgs(const std::string& a_data, std::string& ar_key, std::string& ar_message, bool& ar_cbc)
{
	/* <decode_utf8|raw_bytes|hex_key> <key> <message> */
	const auto l_formatEnd = a_data.find(' ');
	if(l_formatEnd == std::string::npos)
		return false;
	const auto l_keyStart = a_data.find_first_not_of(' ', l_formatEnd);
	if(l_keyStart == std::string::npos)
		return false;
	const auto l_keyEnd = a_data.find(' ', l_keyStart);
	if(l_keyEnd == std::string::npos || l_keyEnd + 1 == a_data.size())
		return false;

	const std::string l_format = a_data.substr(0, l_formatEnd);
	ar_key = a_data.substr(l_keyStart, l_keyEnd - l_keyStart);
	// Consume one separator. Any remaining spaces belong to the message.
	ar_message = a_data.substr(l_keyEnd + 1);
	if(_stricmp(l_format.c_str(), "decode_utf8") == 0 && !DecodeKeyToAnsi(ar_key))
		return false;
	ar_cbc = HasCBCPrefix(ar_key, true);
	if(_stricmp(l_format.c_str(), "hex_key") == 0)
	{
		if(ar_key.size() % 2 != 0)
			return false;
		std::string l_decoded;
		l_decoded.reserve(ar_key.size() / 2);
		for(size_t i = 0; i < ar_key.size(); i += 2)
		{
			const auto l_high = s_hexDigits.find(static_cast<char>(tolower(static_cast<unsigned char>(ar_key[i]))));
			const auto l_low = s_hexDigits.find(static_cast<char>(tolower(static_cast<unsigned char>(ar_key[i + 1]))));
			if(l_high == std::string::npos || l_low == std::string::npos)
				return false;
			l_decoded += static_cast<char>((l_high << 4) | l_low);
		}
		ar_key.swap(l_decoded);
	}
	return !ar_key.empty() && ar_key.find('\0') == std::string::npos;
}


static int _FiSH_DecryptMsg_Internal(std::string& a_data)
{
	std::string l_key, l_message;
	bool l_cbc;
	if(!ParseMessageArgs(a_data, l_key, l_message, l_cbc))
		return MIRC_RET_HALT;

	const bool l_framed = l_message.compare(0, 4, "+OK ") == 0 || l_message.compare(0, 5, "mcps ") == 0;
	if(l_framed)
		l_message.erase(0, l_message[0] == '+' ? 4 : 5);
	const bool l_markedCbc = !l_message.empty() && l_message[0] == '*';
	// Unframed historical calls can omit the CBC marker and use the key mode.
	const bool l_messageCbc = l_markedCbc || (!l_framed && l_cbc);
	const auto l_ini = GetBlowIni();
	if(l_messageCbc != l_cbc && l_ini->GetBool(L"strict_cipher_mode", false))
		return MIRC_RET_HALT;
	if(l_markedCbc)
		l_message.erase(0, 1);

	const size_t l_maxLength = l_ini->MaxKeyLength(l_messageCbc);
	if(l_key.size() > l_maxLength)
		l_key.resize(l_maxLength);

	std::string l_decrypted;
	const int l_result = blowfish_decrypt_auto(l_messageCbc, l_message, l_decrypted, l_key);
	if(l_result == 1)
		l_decrypted += "&";
	else if(l_result < 0)
		l_decrypted += "=[FiSH: DECRYPTION FAILED!]=";
	a_data.swap(l_decrypted);
	return MIRC_RET_DATA_RETURN;
}


MIRC_DLL_EXPORT(FiSH_DecryptMsg10)
{
	if(data && *data)
	{
		std::string l_tmp(data);
		int l_res = _FiSH_DecryptMsg_Internal(l_tmp);

		if(l_res > 0)
		{
			strncpy_s(data, s_maxMircReturnBytes, l_tmp.c_str(), s_maxMircReturnBytes - 1);

			return l_res;
		}
	}

	return MIRC_RET_HALT;
}


MIRC_DLL_EXPORT(FiSH_decrypt_msg)
{
	// de-UTF8 for b/c:
	if(data && *data)
	{
		std::string l_tmp("decode_utf8 ");
		l_tmp.append(data);
		int l_res = _FiSH_DecryptMsg_Internal(l_tmp);

		if(l_res > 0)
		{
			strncpy_s(data, s_maxMircReturnBytes, l_tmp.c_str(), s_maxMircReturnBytes - 1);

			return l_res;
		}
	}

	return 0;
}


static int _FiSH_EncryptMsg_Internal(std::string& a_data)
{
	std::string l_key, l_message, l_encrypted;
	bool l_cbc;
	if(!ParseMessageArgs(a_data, l_key, l_message, l_cbc))
		return MIRC_RET_HALT;
	const size_t l_maxLength = GetBlowIni()->MaxKeyLength(l_cbc);
	if(l_key.size() > l_maxLength)
		return MIRC_RET_HALT;
	blowfish_encrypt_auto(l_cbc, l_message, l_encrypted, l_key);
	if(l_encrypted.empty())
		return MIRC_RET_HALT;
	if(l_cbc)
		l_encrypted.insert(0, "*");
	a_data.swap(l_encrypted);
	return MIRC_RET_DATA_RETURN;
}


MIRC_DLL_EXPORT(FiSH_EncryptMsg10)
{
	if(data && *data)
	{
		std::string l_tmp(data);
		int l_res = _FiSH_EncryptMsg_Internal(l_tmp);

		if(l_res > 0)
		{
			strncpy_s(data, s_maxMircReturnBytes, l_tmp.c_str(), s_maxMircReturnBytes - 1);

			return l_res;
		}
	}

	return MIRC_RET_HALT;
}


MIRC_DLL_EXPORT(FiSH_encrypt_msg)
{
	// de-UTF8 for b/c:
	if(data && *data)
	{
		std::string l_tmp("decode_utf8 ");
		l_tmp.append(data);
		int l_res = _FiSH_EncryptMsg_Internal(l_tmp);

		if(l_res > 0)
		{
			strncpy_s(data, s_maxMircReturnBytes, l_tmp.c_str(), s_maxMircReturnBytes - 1);

			return l_res;
		}
	}

	return MIRC_RET_HALT;
}


MIRC_DLL_EXPORT(FiSH_GetMyIP)
{
	auto l_ini = GetBlowIni();
	std::wstring l_lookupUrl = l_ini->GetStringW(L"MyIP_service");

	if(l_lookupUrl.empty())
		return 0;

	if(l_lookupUrl.compare(0, 8, L"http://") != 0 && l_lookupUrl.compare(0, 9, L"https://") != 0)
		l_lookupUrl.insert(0, L"http://");

	const std::string l_response = HttpDownloadTextFile(l_lookupUrl);

	if(!l_response.empty())
	{
		std::string::size_type l_pos = l_response.find_first_of("0123456789");

		while(l_pos != std::string::npos)
		{
			std::string l_buf;

			while(l_pos < l_response.size() && (isdigit(l_response[l_pos]) || l_response[l_pos] == '.'))
			{
				l_buf += l_response[l_pos];
				l_pos++;
			}

			unsigned short ip[4];

			if(l_buf.size() >= 7 && sscanf_s(l_buf.c_str(), "%hu.%hu.%hu.%hu", &ip[0], &ip[1], &ip[2], &ip[3]) == 4)
			{
				if((ip[0] > 0) && (ip[0] < 255) && (ip[1] < 255) && (ip[2] < 255) && (ip[3] < 255))
				{
					strcpy_s(data, s_maxMircReturnBytes, l_buf.c_str());
					return 3;
				}
			}

			l_pos = l_response.find_first_of("0123456789", l_pos + 1);
		}
	}

	return MIRC_RET_CONTINUE;
}


MIRC_DLL_EXPORT(INI_GetBool)
{
	if(!data || !*data)
		return 0;

	const string_vector l_data = SplitString(data, " ", 2);
	const std::wstring l_key = UnicodeFromCp(CP_UTF8, l_data[0]);
	bool l_default = (l_data.size() > 1 && atoi(l_data[1].c_str()) != 0);

	auto l_ini = GetBlowIni();
	bool b = l_ini->GetBool(l_key.c_str(), l_default);

	sprintf_s(data, s_maxMircReturnBytes, "%d", (b ? 1 : 0));

	return MIRC_RET_DATA_RETURN;
}


static bool STR_TO_BOOL(const char* s)
{
	return (!s || !*s || *s == '0' || !_stricmp(s, "false") ? 0 : 1);
}

static bool STR_TO_BOOL(const std::string& ss)
{
	return STR_TO_BOOL(ss.c_str());
}


MIRC_DLL_EXPORT(INI_SetBool)
{
	if(data && *data)
	{
		const string_vector l_data = SplitString(data, " ", 2);

		if(l_data.size() >= 2)
		{
			auto l_ini = GetBlowIni();

			const std::wstring l_key = UnicodeFromCp(CP_UTF8, l_data[0]);

			l_ini->SetInt(l_key.c_str(), STR_TO_BOOL(l_data[1]));

			return MIRC_RET_CONTINUE;
		}
	}

	return MIRC_RET_HALT;
}


MIRC_DLL_EXPORT(INI_GetSectionBool)
{
	if(data && *data)
	{
		const string_vector l_data = SplitString(data, " ", 4);
		/* <network> <contact> <keyname> <default> */

		if(l_data.size() >= 4)
		{
			auto l_ini = GetBlowIni();

			const std::wstring l_key = UnicodeFromCp(CP_UTF8, l_data[2]);
			bool l_default = STR_TO_BOOL(l_data[3]);

			bool b = l_ini->GetSectionBool(l_data[0], l_data[1], l_key.c_str(), l_default);

			sprintf_s(data, s_maxMircReturnBytes, "%d", (b ? 1 : 0));

			return MIRC_RET_DATA_RETURN;
		}
	}

	return MIRC_RET_HALT;
}


MIRC_DLL_EXPORT(INI_SetSectionBool)
{
	if(data && *data)
	{
		const string_vector l_data = SplitString(data, " ", 4);
		/* <network> <contact> <keyname> <value> */

		if(l_data.size() >= 4)
		{
			auto l_ini = GetBlowIni();

			const std::wstring l_key = UnicodeFromCp(CP_UTF8, l_data[2]);
			bool l_value = STR_TO_BOOL(l_data[3]);

			l_ini->SetSectionBool(l_data[0], l_data[1], l_key.c_str(), l_value);

			return MIRC_RET_CONTINUE;
		}
	}

	return MIRC_RET_HALT;
}


MIRC_DLL_EXPORT(NetworkDebugInfo)
{
	std::string l_networks;

	::EnterCriticalSection(&s_socketMapLock);
	for (const auto& it : s_socketMap)
	{
		l_networks += "[" + it.second + "]";
	}
	::LeaveCriticalSection(&s_socketMapLock);

	sprintf_s(data, s_maxMircReturnBytes, "/echo -a *** Active networks: %s",
		l_networks.substr(0, s_maxMircReturnBytes - 32).c_str());

	return MIRC_RET_DATA_COMMAND;
}


/* engine struct for fish_inject.dll */

DECLARE_FISH_INJECT_ENGINE(g_engine_export, _OnIncomingIRCLine, _OnOutgoingIRCLine, _OnSocketClosed, _FreeString, false, "FiSH")

static PFishEngineRegistration reg;

/* mIRC interface to keep DLL loaded */

MIRC_EXPORT_SIG(void) LoadDll(LOADINFO* info)
{
	info->mKeep = TRUE;
	info->mUnicode = FALSE; // no point in converting back&forth with sockets
	s_maxMircReturnBytes = info->mBytes;

	reg = std::make_shared<CFishEngineRegistration>(&g_engine_export);
	
	const bool l_registered = reg->RegisterUsingDll();
	s_engineRegistered.store(l_registered);
	if (!l_registered)
	{
		::MessageBoxW(info->mHwnd, L"FiSH10_DLL failed to register engine w/ inject component!", L"This is likely a bug", MB_ICONERROR | MB_OK);

		// info->mKeep = FALSE;
		// still keep to avoid error messages showing up again and again.
	}

}

MIRC_EXPORT_SIG(int) UnloadDll(int mTimeout)
{
	if (mTimeout == 1)
	{
		// unload not ok:
		return 0;
	}
	else
	{
		// forced unload.
		s_engineRegistered.store(false);
		reg.reset();

		return 0;
	}
}


/* call for mIRC to show compililation date */

#define FISH_MAIN_VERSION "*** FiSH 10.23.1 *** by [c&f]\xA0\xA0*** fish_10.dll\xA0\xA0\xA0\xA0\xA0""compiled " __DATE__ " " __TIME__ " ***"

MIRC_DLL_EXPORT(_callMe)
{
	strcpy_s(data, s_maxMircReturnBytes, "/echo -a " FISH_MAIN_VERSION);

	// enforce costly DH_check call during startup.
	// see https://github.com/flakes/mirc_fish_10/issues/61
	std::thread([] {
		std::string dummyPriv, dummyPub;

		DH1080_Generate(dummyPriv, dummyPub);
	}).detach();

	return MIRC_RET_DATA_COMMAND;
}

MIRC_DLL_EXPORT(FiSH_GetVersion)
{
	strcpy_s(data, s_maxMircReturnBytes, FISH_MAIN_VERSION);

	return MIRC_RET_DATA_RETURN;
}

MIRC_DLL_EXPORT(FiSH_WriteAlias10)
{
	if(!data || !*data)
		return MIRC_RET_CONTINUE;

	/* <network> <target> <source> [nick] */
	const string_vector l_args = SplitString(data, " ");
	const bool l_trackNick = l_args.size() == 4 && l_args[3] == "nick";
	const auto l_result = (l_args.size() == 3 || l_trackNick)
		? GetBlowIni()->WriteBlowAlias(l_args[0], l_args[1], l_args[2], l_trackNick)
		: CBlowIni::AliasWriteResult::Error;
	if(l_trackNick)
		return MIRC_RET_CONTINUE;

	const char* l_status = "error";
	if(l_result == CBlowIni::AliasWriteResult::Ok)
		l_status = "ok";
	else if(l_result == CBlowIni::AliasWriteResult::NoKey)
		l_status = "no_key";
	strcpy_s(data, s_maxMircReturnBytes, l_status);
	return MIRC_RET_DATA_RETURN;
}

/* DllMain for initialization purposes */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch(fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		::InitializeCriticalSection(&s_iniLock);
		::InitializeCriticalSection(&s_socketMapLock);
		break;
	case DLL_PROCESS_DETACH:
		::DeleteCriticalSection(&s_iniLock);
		::DeleteCriticalSection(&s_socketMapLock);
		break;
	}

	return TRUE;
}
