// FiSH encryption module for irssi, v1.00

#include "FiSH.h"



// load base64 blowfish key for contact
// if theKey is NULL, only a test is made (= IsKeySetForContact)
BOOL LoadKeyForContact(const char *contactPtr, char *theKey)
{
	char contactName[CONTACT_SIZE]="", tmpKey[KEYBUF_SIZE]="";
	BOOL bRet=FALSE;


	FixIniSection(contactPtr, contactName);	// replace '[' and ']' with '~' in contact name

	GetPrivateProfileString(contactName, "key", "", tmpKey, KEYBUF_SIZE, iniPath);
	if(strlen(tmpKey) < 16) return FALSE;		// don't process, encrypted key not found in ini

	if(strncmp(tmpKey, "+OK ", 4)==0)
	{
		// encrypted key found
		if(theKey)
		{
			// if it's not just a test, lets decrypt the key
			decrypt_string((char *)iniKey, tmpKey+4, theKey, strlen(tmpKey+4));
		}

		bRet=TRUE;
	}

	ZeroMemory(tmpKey, KEYBUF_SIZE);
	return bRet;
}



// encrypt a message and store in bf_dest (using key for target)
int FiSH_encrypt(const SERVER_REC *server, const char *msg_ptr, const char *target, char *bf_dest)
{
	char theKey[KEYBUF_SIZE]="";


	if(IsNULLorEmpty(msg_ptr) || bf_dest==NULL || IsNULLorEmpty(target)) return 0;

	if(GetBlowIniSwitch("FiSH", "process_outgoing", "1") == 0) return 0;

	if(LoadKeyForContact(target, theKey)==FALSE) return 0;

	strcpy(bf_dest, "+OK ");

	encrypt_string(theKey, msg_ptr, bf_dest+4, strlen(msg_ptr));

	ZeroMemory(theKey, KEYBUF_SIZE);
	return 1;
}



// decrypt a base64 cipher text (using key for target)
int FiSH_decrypt(const SERVER_REC *server, char *msg_ptr, char *msg_bak, const char *target)
{
	char contactName[CONTACT_SIZE]="", theKey[KEYBUF_SIZE]="", bf_dest[1000]="";
	char myMark[20]="", markPos[20]="", *recoded;
	int msg_len, i, mark_broken_block=0, action_found=0;


	if(IsNULLorEmpty(msg_ptr) || msg_bak==NULL || IsNULLorEmpty(target)) return 0;

	if(GetBlowIniSwitch("FiSH", "process_incoming", "1") == 0) return 0;

	if(strncmp(msg_ptr, "+OK ", 4)==0) msg_ptr += 4;
	else if(strncmp(msg_ptr, "mcps ", 5)==0) msg_ptr += 5;
	else return 0;		// don't process, blowcrypt-prefix not found

	// Verify base64 string
	msg_len=strlen(msg_ptr);
	if((strspn(msg_ptr, B64) != msg_len) || (msg_len < 12)) return 0;

	if(LoadKeyForContact(target, theKey)==FALSE) return 0;

	// usually a received message does not exceed 512 chars, but we want to prevent evil buffer overflow
	if(msg_len >= (int)(sizeof(bf_dest)*1.5)) msg_ptr[(int)(sizeof(bf_dest)*1.5)-20]='\0';

	// block-align blowcrypt strings if truncated by IRC server (each block is 12 chars long)
	// such a truncated block is destroyed and not needed anymore
	if(msg_len != (msg_len/12)*12)
	{
		msg_len=(msg_len/12)*12;
		msg_ptr[msg_len]='\0';
		GetPrivateProfileString("FiSH", "mark_broken_block", " \002&\002", myMark, sizeof(myMark), iniPath);
		if(*myMark=='\0' || isNoChar(*myMark)) mark_broken_block=0;
		else mark_broken_block=1;
	}

	decrypt_string(theKey, msg_ptr, bf_dest, msg_len);
	ZeroMemory(theKey, KEYBUF_SIZE);

	if(*bf_dest=='\0') return 0;	// don't process, decrypted msg is bad

#ifdef FiSH_USE_IRSSI_RECODE
	// recode message again, last time it was the encrypted message...
	if(settings_get_bool("recode") && server!=NULL)
	{
		recoded = recode_in(server, bf_dest, target);
		if(recoded)
		{
			strncpy(bf_dest, recoded, sizeof(bf_dest));
			ZeroMemory(recoded, strlen(recoded));
			g_free(recoded);
		}
	}
#endif

	i=0;
	while(bf_dest[i] != 0x0A && bf_dest[i] != 0x0D && bf_dest[i] != '\0') i++;
	bf_dest[i]='\0';	// in case of wrong key, decrypted message might have control characters -> cut message

	if(strncmp(bf_dest, "\001ACTION ", 8)==0)
	{
		// ACTION message found
		if(bf_dest[i-1] == '\001') bf_dest[i-1] = '\0';	// remove 0x01 control character
		action_found = 1;
	}

	// append broken-block-mark?
	if(mark_broken_block) strcat(bf_dest, myMark);

	// append crypt-mark?
	FixIniSection(target, contactName);	// replace '[' and ']' with '~' in contact name
	if(GetBlowIniSwitch(contactName, "mark_encrypted", "1") != 0)
	{
		GetPrivateProfileString("FiSH", "mark_encrypted", "", myMark, sizeof(myMark), iniPath);	// global setting
		if(*myMark != '\0')
		{
			GetPrivateProfileString("FiSH", "mark_position", "0", markPos, sizeof(markPos), iniPath);
			if(*markPos=='0' || action_found) strcat(bf_dest, myMark);		// append mark at the end (default for ACTION messages)
			else
			{	// prefix mark
				i=strlen(myMark);
				memmove(bf_dest+i, bf_dest, strlen(bf_dest)+1);
				strncpy(bf_dest, myMark, i);
			}
		}
	}

	strcpy(msg_bak, bf_dest);	// copy decrypted message back (overwriting the base64 cipher text)
	ZeroMemory(bf_dest, sizeof(bf_dest));

	return 1;
}



void decrypt_msg(SERVER_REC *server, char *msg, const char *nick, const char *address, const char *target)
{
	const char *contactPtr, *msg_bak=msg;
	char contactName[CONTACT_SIZE]="";


	if(msg==NULL || target==NULL || nick==NULL) return;

#ifdef FiSH_DECRYPT_ZNC_LOGS
	if(IsZNCtimestamp(msg)) msg += 11;
#endif

	//channel?
	if(ischannel(*target)) contactPtr=target;
	else if(strcmp(nick, "-psyBNC")==0)
	{	// psyBNC log message found		// <-psyBNC> Nw~Thu Mar 29 15:02:45 :(yourmom!ident@get.se) +OK e3454451hbadA0

		msg=strstr(msg, " :(")+3;	// points to nick!ident@host in psybnc log
		if(msg==(char *)3) return;
		ExtractRnick(contactName, msg);
		msg=strchr(msg, ' ')+1;
		if(msg==(char *)1) return;
		contactPtr = contactName;
	}
	else if(strcmp(nick, "-sBNC")==0)
	{	// sBNC log message found (PRIVMSG)		// <-sBNC> Sun Sep  1 13:37:00 2007 someone (some@one.us): +OK Mp1p8.qYxFN1

		if((msg=strstr(msg, " ("))==NULL) return;
		else msg--;		// points to the last char of the nick

		while(*msg!='\0' && *msg!=' ' && msg > msg_bak) msg--;

		if(*msg==' ') msg++;	// now points to the first char of the nick
		else return;

		ExtractRnick(contactName, msg);

		if((msg=strstr(msg, "): "))==NULL) return;	// find metadata end
		msg += 3;	// now points to encrypted message

		contactPtr = contactName;
	}
	else contactPtr=nick;

	if(FiSH_decrypt(server, msg, msg, contactPtr))
	{
		if(strncmp(msg_bak, "\001ACTION ", 8)==0)
		{
			// ACTION message found
			signal_stop();
			signal_emit("message irc action", 5, server, msg_bak+8, nick, address, target);
		}
	}
}



void encrypt_msg(SERVER_REC *server, char *target, char *msg, char *orig_target)
{
	char bf_dest[800]="", *plainMsg;


	if(IsNULLorEmpty(msg) || IsNULLorEmpty(target)) return;
	if(LoadKeyForContact(target, NULL)==FALSE) return;


	plainMsg = IsPlainPrefix(msg);
	if(plainMsg)
	{
		signal_continue(4, server, target, plainMsg, orig_target);
		return;
	}

	// generally cut a message to a size of 512 byte, as everything above will never arrive complete anyway
	if(strlen(msg) > 512) msg[512]='\0';

	if(FiSH_encrypt(server, msg, target, bf_dest)==1)
	{	// message was encrypted
		bf_dest[512]='\0';
		signal_continue(4, server, target, bf_dest, orig_target);
	}
}



// format outgoing (encrypted) messages (add crypt-mark or remove plain-prefix)
void format_msg(SERVER_REC *server, char *msg, char *target, char *orig_target)
{
	char contactName[CONTACT_SIZE]="", myMark[20]="", markPos[20]="", formattedMsg[800]="";
	int i;
	char *plainMsg;


	if(IsNULLorEmpty(msg) || IsNULLorEmpty(target)) return;
	if(GetBlowIniSwitch("FiSH", "process_outgoing", "1") == 0) return;
	if(LoadKeyForContact(target, NULL)==FALSE) return;


	plainMsg = IsPlainPrefix(msg);
	if(plainMsg)
	{
		signal_continue(4, server, plainMsg, target, orig_target);
		return;
	}


	// generally cut a message to a size of 512 byte, as everything above will never arrive complete anyway
	if(strlen(msg) > 512) msg[512]='\0';


	// append crypt-mark?
	FixIniSection(target, contactName);	// replace '[' and ']' with '~' in contact name
	if(GetBlowIniSwitch(contactName, "mark_encrypted", "1") != 0)
	{
		GetPrivateProfileString("FiSH", "mark_encrypted", "", myMark, sizeof(myMark), iniPath);	// global setting
		if(*myMark != '\0')
		{
			strcpy(formattedMsg, msg);

			GetPrivateProfileString("FiSH", "mark_position", "0", markPos, sizeof(markPos), iniPath);
			if(*markPos=='0') strcat(formattedMsg, myMark);		//append mark at the end
			else
			{	// prefix mark
				i=strlen(myMark);
				memmove(formattedMsg+i, formattedMsg, strlen(formattedMsg)+1);
				strncpy(formattedMsg, myMark, i);
			}

			signal_continue(4, server, formattedMsg, target, orig_target);

			ZeroMemory(formattedMsg, sizeof(formattedMsg));
		}
	}

	return;
}



// decrypt NOTICE messages (and forward DH1080 key-exchange)
void decrypt_notice(SERVER_REC *server, char *msg, char *nick, char *address, char *target)
{
	char *DH1024warn;

	if(strncmp(msg, "DH1024_", 7)==0)
	{
		DH1024warn = "\002FiSH:\002 Received \002old DH1024\002 public key from you! Please update to latest version: http://fish.sekure.us";
		signal_stop();
		irc_send_cmdv((IRC_SERVER_REC *)server, "NOTICE %s :%s\n", nick, DH1024warn);
		signal_emit("message irc own_notice", 3, server, DH1024warn, nick);
		return;
	}

	if(strncmp(msg, "DH1080_", 7)==0)
	{
		DH1080_received(server, msg, nick, address, target);
		return;
	}

#ifdef FiSH_DECRYPT_ZNC_LOGS
	if(IsZNCtimestamp(msg)) msg += 11;
#endif

	FiSH_decrypt(server, msg, msg, ischannel(*target) ? target : nick);
}



void decrypt_action(SERVER_REC *server, char *msg, char *nick, char *address, char *target)
{
	if(target==NULL) return;

	FiSH_decrypt(server, msg, msg, ischannel(*target) ? target : nick);
}



void decrypt_topic(SERVER_REC *server, char *channel, char *topic, char *nick, char *address)
{
	FiSH_decrypt(server, topic, topic, channel);
}



void decrypt_changed_topic(CHANNEL_REC *chan_rec)
{
	FiSH_decrypt(NULL, chan_rec->topic, chan_rec->topic, chan_rec->name);
}



void raw_handler(SERVER_REC *server, char *data)
{
	char channel[CONTACT_SIZE], *ptr, *ptr_bak;
	int len;

	if(IsNULLorEmpty(data)) return;

	ptr=strchr(data, ' ');	// point to command
	if(ptr==NULL) return;
	ptr++;

	if(strncmp(ptr, "332 ", 4)!=0) return;	// 332 = TOPIC

	ptr_bak=ptr;
	ptr=strchr(ptr, '#');	// point to #channel
	if(ptr==NULL)
	{
		ptr=strchr(ptr_bak, '&');	// point to &channel
		if(ptr==NULL)
		{
			ptr=strchr(ptr_bak, '!');	// point to !channel
			if(ptr==NULL) return;
		}
	}

	len=strchr(ptr, ' ')-ptr;
	if(len >= CONTACT_SIZE-2) return;	// channel string too long, something went wrong
	strncpy(channel, ptr, len);
	channel[len]='\0';

	ptr=strchr(ptr, ':');	// point to topic msg start
	if(ptr==NULL) return;
	ptr++;

	FiSH_decrypt(server, ptr, ptr, channel);
}



// New command: /notice+ <nick/#channel> <notice message>
void cmd_crypt_notice(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	char bf_dest[1000]="", *msg;
	const char *target;
	void *free_arg=NULL;


	if(data==NULL || (strlen(data) < 3)) goto notice_error;
	if(!cmd_get_params(data, &free_arg, 1, &target)) goto notice_error;

	msg = strchr(data, ' ');
	if (IsNULLorEmpty(target) || IsNULLorEmpty(msg)) goto notice_error;

	msg++; // point to the notice message


	// generally refuse a notice size of more than 512 byte, as everything above will never arrive complete anyway
	if(strlen(msg) >= 512)
	{
		printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /notice+ \002error\002: message argument exceeds buffer size!");
		goto notice_error;
	}

	if(FiSH_encrypt(server, msg, target, bf_dest)==0)
	{
		printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /notice+ \002error\002: Encryption disabled or no key found for %s.", target);
		goto notice_error;
	}

	bf_dest[512]='\0';
	irc_send_cmdv((IRC_SERVER_REC *)server, "NOTICE %s :%s\n", target, bf_dest);

	signal_emit("message irc own_notice", 3, server, msg, target);
	cmd_params_free(free_arg);
	return;

notice_error:
	if(free_arg) cmd_params_free(free_arg);
	printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
			"\002FiSH:\002 Usage: /notice+ <nick/#channel> <notice message>");
}



// New command: /me+ <action message>
void cmd_crypt_action(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{	// New command: /me+ <action message>
	char bf_dest[1000]="";
	const char *target;


	if(data==NULL || (strlen(data) < 2)) goto action_error;

	if(item!=NULL) target=window_item_get_target(item);
	else goto action_error;


	// generally refuse an action size of more than 512 byte, as everything above will never arrive complete anyway
	if(strlen(data) >= 512)
	{
		printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /me+ \002error\002: message argument exceeds buffer size!");
		return;
	}

	if(FiSH_encrypt(server, (char *)data, target, bf_dest)==0)
	{
		printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /me+ \002error\002: Encryption disabled or no key found for %s.", target);
		return;
	}

	bf_dest[512]='\0';
	irc_send_cmdv((IRC_SERVER_REC *)server, "PRIVMSG %s :\001ACTION %s\001\n", target, bf_dest);

	signal_emit("message irc own_action", 3, server, data, target);
	return;

action_error:
	printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
			"\002FiSH:\002 Usage: /me+ <action message>");
}



// set encrypted topic for current channel, irssi syntax: /topic+ <your topic>
void cmd_crypt_TOPIC(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	char bf_dest[1000]="";
	const char *target;


	if(data==0 || *data=='\0') goto topic_error;
	if(item!=NULL) target=window_item_get_target(item);
	else goto topic_error;


	if(!ischannel(*target))
	{
		printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 Please change to the channel window where you want to set the topic!");
		goto topic_error;
	}

	// generally refuse a topic size of more than 512 byte, as everything above will never arrive complete anyway
	if(strlen(data) >= 512)
	{
		printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /topic+ error: topic length exceeds buffer size!");
		goto topic_error;
	}

	// encrypt a message (using key for target)
	if(FiSH_encrypt(server, (char *)data, target, bf_dest)==0)
	{
		printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /topic+ error: Encryption disabled or no key found for %s.", target);
		goto topic_error;
	}

	bf_dest[512]='\0';
	irc_send_cmdv((IRC_SERVER_REC *)server, "TOPIC %s :%s\n", target, bf_dest);
	return;

topic_error:
	printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
			"\002FiSH:\002 Usage: /topic+ <your new topic>");
}



void cmd_helpfish(const char *arg, SERVER_REC *server, WI_ITEM_REC *item)
{
	printtext(NULL, NULL, MSGLEVEL_CRAP,
		"\n\002FiSH HELP:\002 For more information read FiSH-irssi.txt :)\n\n"
		" /topic+ <your new topic>\n"
		" /notice+ <nick/#channel> <notice message>\n"
		" /me+ <your action message>\n"
		" /key [<nick/#channel>]\n"
		" /setkey [<nick/#channel>] <sekure_key>\n"
		" /delkey <nick/#channel>\n"
		" /keyx [<nick>] (DH1080 KeyXchange)\n"
		" /setinipw <sekure_blow.ini_password>\n"
		" /unsetinipw\n");
}



void cmd_setinipw(const char *iniPW, SERVER_REC *server, WI_ITEM_REC *item)
{
	int i=0, pw_len, re_enc=0;
	char B64digest[50], SHA256digest[35];
	char bfKey[512], new_iniKey[KEYBUF_SIZE], old_iniKey[KEYBUF_SIZE], *fptr, *ok_ptr, line_buf[1000], iniPath_new[300];
	FILE *h_ini, *h_ini_new;


	if(!unsetiniFlag)
	{
		pw_len=strlen(iniPW);
		if(pw_len < 1 || pw_len > sizeof(new_iniKey))
		{
			printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
					"\002FiSH:\002 No parameters. Usage: /setinipw <sekure_blow.ini_password>");
			return;
		}

		if(strfcpy(new_iniKey, (char *)iniPW, sizeof(new_iniKey))==NULL) return;
		ZeroMemory(iniPW, pw_len);
		pw_len=strlen(new_iniKey);

		if(pw_len < 8)
		{
			printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
					"\002FiSH:\002 Password too short, at least 8 characters needed! Usage: /setinipw <sekure_blow.ini_password>");
			return;
		}

		SHA256_memory(new_iniKey, pw_len, SHA256digest);
		ZeroMemory(new_iniKey, sizeof(new_iniKey));
		for(i=0;i<40872;i++) SHA256_memory(SHA256digest, 32, SHA256digest);
		htob64(SHA256digest, B64digest, 32);
	}

	strcpy(old_iniKey, iniKey);

	if(unsetiniFlag) strcpy(iniKey, default_iniKey);	// unsetinipw -> use default blow.ini key
	else strcpy(iniKey, B64digest);	// this is used for encrypting blow.ini

	for(i=0;i<30752;i++) SHA256_memory(SHA256digest, 32, SHA256digest);
	htob64(SHA256digest, B64digest, 32);	// this is used to verify the entered password
	ZeroMemory(SHA256digest, sizeof(SHA256digest));


	// re-encrypt blow.ini with new password
	strcpy(iniPath_new, iniPath);
	strcat(iniPath_new, "_new");
	h_ini_new=fopen(iniPath_new, "w");
	h_ini=fopen(iniPath,"r");
	if(h_ini && h_ini_new)
	{
		while (!feof(h_ini))
		{
			fptr=fgets(line_buf, sizeof(line_buf)-2, h_ini);
			if(fptr)
			{
				ok_ptr=strstr(line_buf, "+OK ");
				if(ok_ptr)
				{
					re_enc=1;
					strtok(ok_ptr+4, " \n\r");
					decrypt_string(old_iniKey, ok_ptr+4, bfKey, strlen(ok_ptr+4));
					ZeroMemory(ok_ptr+4, strlen(ok_ptr+4)+1);
					encrypt_string(iniKey, bfKey, ok_ptr+4, strlen(bfKey));
					strcat(line_buf, "\n");
				}
				if(fprintf(h_ini_new, "%s", line_buf) < 0)
				{
					ZeroMemory(B64digest, sizeof(B64digest));
					ZeroMemory(bfKey, sizeof(bfKey));
					ZeroMemory(line_buf, sizeof(line_buf));
					ZeroMemory(old_iniKey, sizeof(old_iniKey));
					fclose(h_ini);
					fclose(h_ini_new);
					remove(iniPath_new);

					printtext(server, item!=NULL ? window_item_get_target(item) : NULL,	MSGLEVEL_CRAP,
							"\002FiSH ERROR:\002 Unable to write new blow.ini, probably out of disc space.");

					return;
				}
			}
		}

		ZeroMemory(bfKey, sizeof(bfKey));
		ZeroMemory(line_buf, sizeof(line_buf));
		ZeroMemory(old_iniKey, sizeof(old_iniKey));
		fclose(h_ini);
		fclose(h_ini_new);
		remove(iniPath);
		rename(iniPath_new, iniPath);
	}
	else return;

	if(WritePrivateProfileString("FiSH", "ini_password_Hash", B64digest, iniPath) == -1)
	{
		ZeroMemory(B64digest, sizeof(B64digest));
		printtext(server, item!=NULL ? window_item_get_target(item) : NULL,	MSGLEVEL_CRAP,
				"\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
		return;
	}

	ZeroMemory(B64digest, sizeof(B64digest));

	if(re_enc) printtext(server, item!=NULL ? window_item_get_target(item) : NULL,
					MSGLEVEL_CRAP, "\002FiSH: Re-encrypted blow.ini\002 with new password.");

	if(!unsetiniFlag) printtext(server, item!=NULL ? window_item_get_target(item) : NULL,
						MSGLEVEL_CRAP, "\002FiSH:\002 blow.ini password hash saved.");
}



// Change back to default blow.ini password, irssi syntax: /unsetinipw
static void cmd_unsetinipw(const char *arg, SERVER_REC *server, WI_ITEM_REC *item)
{
	unsetiniFlag=1;
	cmd_setinipw("Some_boogie_dummy_key", server, item);
	unsetiniFlag=0;

	if(WritePrivateProfileString("FiSH", "ini_password_Hash", "\0", iniPath) == -1)
	{
		printtext(server, item!=NULL ? window_item_get_target(item) : NULL,	MSGLEVEL_CRAP,
			"\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
		return;
	}

	printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
		"\002FiSH:\002 Changed back to default blow.ini password, you won't have to enter it on start-up anymore!");
}



void cmd_setkey(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	char contactName[CONTACT_SIZE]="", encryptedKey[150]="";
	const char *target, *key;
	void *free_arg;


	if (IsNULLorEmpty(data))
	{
		printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
			"\002FiSH:\002 No parameters. Usage: /setkey [<nick/#channel>] <sekure_key>");
		return;
	}

	if (!cmd_get_params(data, &free_arg, 2, &target, &key)) return;

	if (*target=='\0')
	{
		printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
				"\002FiSH:\002 No parameters. Usage: /setkey [<nick/#channel>] <sekure_key>");
		cmd_params_free(free_arg);
		return;
	}

	if (*key=='\0') {
		// one paramter given - it's the key
		key = target;
		if (item != NULL) target = window_item_get_target(item);
		else
		{
			printtext(NULL, NULL, MSGLEVEL_CRAP,
					"\002FiSH:\002 Please define nick/#channel. Usage: /setkey [<nick/#channel>] <sekure_key>");
			cmd_params_free(free_arg);
			return;
		}
	}

	FixIniSection(target, contactName);

	encrypt_key((char *)key, encryptedKey);

	if(WritePrivateProfileString(contactName, "key", encryptedKey, iniPath) == -1)
	{
		ZeroMemory(encryptedKey, sizeof(encryptedKey));
		printtext(server, item!=NULL ? window_item_get_target(item) : NULL,	MSGLEVEL_CRAP,
				"\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
		cmd_params_free(free_arg);
		return;
	}

	ZeroMemory(encryptedKey, sizeof(encryptedKey));

	printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
			"\002FiSH:\002 Key for %s successfully set!", target);

	cmd_params_free(free_arg);
}



void cmd_delkey(const char *target, SERVER_REC *server, WI_ITEM_REC *item)
{
	char contactName[CONTACT_SIZE]="";


	if (IsNULLorEmpty(target))
	{
		printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
				"\002FiSH:\002 No parameters. Usage: /delkey <nick/#channel>");
		return;
	}

	if(strfcpy(contactName, (char *)target, CONTACT_SIZE)==NULL) return;
	FixIniSection(NULL, contactName);

	if(WritePrivateProfileString(contactName, "key", "\0", iniPath) == -1)
	{
		printtext(server, item!=NULL ? window_item_get_target(item) : NULL,	MSGLEVEL_CRAP,
			"\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
		return;
	}

	printtext(server, item!=NULL ? window_item_get_target(item) : NULL,	MSGLEVEL_CRAP,
		"\002FiSH:\002 Key for %s successfully removed!", target);
}



void cmd_key(const char *target, SERVER_REC *server, WI_ITEM_REC *item)
{
	char contactName[CONTACT_SIZE]="", theKey[KEYBUF_SIZE]="";


	if(IsNULLorEmpty(target))
	{
		if (item!=NULL) target=window_item_get_target(item);
		else
		{
			printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Please define nick/#channel. Usage: /key <nick/#channel>");
			return;
		}
	}

	if(strfcpy(contactName, (char *)target, CONTACT_SIZE)==NULL) return;

	if(LoadKeyForContact(contactName, theKey)==FALSE)
	{
		ZeroMemory(theKey, KEYBUF_SIZE);
		printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
			"\002FiSH:\002 Key for %s not found or invalid!", target);
		return;
	}

	printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 Key for %s: %s", target, theKey);

	ZeroMemory(theKey, KEYBUF_SIZE);
}



void cmd_keyx(const char *target, SERVER_REC *server, WI_ITEM_REC *item)
{
	if(IsNULLorEmpty(target))
	{
		if(item!=NULL) target = window_item_get_target(item);
		else
		{
			printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Please define nick/#channel. Usage: /keyx <nick/#channel>");
			return;
		}
	}

	if(ischannel(*target))
	{
		printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 KeyXchange does not work for channels!");
		return;
	}

	DH1080_gen(g_myPrivKey, g_myPubKey);

	irc_send_cmdv((IRC_SERVER_REC *)server, "NOTICE %s :%s %s", target, "DH1080_INIT", g_myPubKey);

	printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
			"\002FiSH:\002 Sent my DH1080 public key to %s, waiting for reply ...", target);
}



void DH1080_received(SERVER_REC *server, char *msg, char *nick, char *address, char *target)
{
	int i;
	char hisPubKey[300], contactName[CONTACT_SIZE]="", encryptedKey[KEYBUF_SIZE]="";


	if(ischannel(*target) || ischannel(*nick)) return;	// no KeyXchange for channels...
	i=strlen(msg);
	if(i<191 || i>195) return;

	if(strncmp(msg, "DH1080_INIT ", 12)==0)
	{
		strcpy(hisPubKey, msg+12);
		if(strspn(hisPubKey, B64ABC) != strlen(hisPubKey)) return;

		if(query_find(server, nick)==NULL)
		{	// query window not found, lets create one
			keyx_query_created=1;
			irc_query_create(server->tag, nick, TRUE);
			keyx_query_created=0;
		}

		printtext(server, nick, MSGLEVEL_CRAP, "\002FiSH:\002 Received DH1080 public key from %s, sending mine...", nick);

		DH1080_gen(g_myPrivKey, g_myPubKey);
		irc_send_cmdv((IRC_SERVER_REC *)server, "NOTICE %s :%s %s", nick, "DH1080_FINISH", g_myPubKey);
	}
	else if(strncmp(msg, "DH1080_FINISH ", 14)==0) strcpy(hisPubKey, msg+14);
	else return;

	if(DH1080_comp(g_myPrivKey, hisPubKey)==0) return;
	signal_stop();

	FixIniSection(nick, contactName);

	encrypt_key(hisPubKey, encryptedKey);
	ZeroMemory(hisPubKey, sizeof(hisPubKey));

	if(WritePrivateProfileString(contactName, "key", encryptedKey, iniPath) == -1)
	{
		ZeroMemory(encryptedKey, KEYBUF_SIZE);
		printtext(server, nick,	MSGLEVEL_CRAP, "\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
		return;
	}

	ZeroMemory(encryptedKey, KEYBUF_SIZE);

	printtext(server, nick, MSGLEVEL_CRAP, "\002FiSH:\002 Key for %s successfully set!", nick);
}



// perform auto-keyXchange only for known people
void do_auto_keyx(QUERY_REC *query, int automatic)
{
	if(keyx_query_created)
		return;	// query was created by FiSH

	if(GetBlowIniSwitch("FiSH", "auto_keyxchange", "1") == 0)
		return;

	if(LoadKeyForContact(query->name, NULL))
		cmd_keyx(query->name, query->server, NULL);
}



// copy key for old nick to use with the new one
void query_nick_changed(QUERY_REC *query, char *orignick)
{
	char theKey[KEYBUF_SIZE]="", contactName[CONTACT_SIZE]="";


	if(GetBlowIniSwitch("FiSH", "nicktracker", "1") == 0) return;

	if(orignick==NULL || strcasecmp(orignick, query->name)==0) return;	// same nick, different case?

	if(LoadKeyForContact(orignick, theKey)==FALSE)
		return;	// see if there is a key for the old nick

	FixIniSection(query->name, contactName);

	if(WritePrivateProfileString(contactName, "key", theKey, iniPath) == -1)
		printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");

	ZeroMemory(theKey, KEYBUF_SIZE);
}



void fish_init(void)
{
	char iniPasswordHash[50], SHA256digest[35], B64digest[50], *iniPass_ptr;
	int i;


	strcpy(iniPath, get_irssi_config());	// path to irssi config file
	strcpy(tempPath, iniPath);
	strcpy(strrchr(iniPath, '/'), blow_ini);
	strcpy(strrchr(tempPath, '/'), "/temp_FiSH.$$$");

	if(DH1080_Init()==FALSE) return;

	GetPrivateProfileString("FiSH", "ini_Password_hash", "0", iniPasswordHash, sizeof(iniPasswordHash), iniPath);
	if(strlen(iniPasswordHash) == 43)
	{
		iniPass_ptr = getpass(" --> Please enter your blow.ini password: ");
		strcpy(iniKey, iniPass_ptr);
		ZeroMemory(iniPass_ptr, strlen(iniPass_ptr));
		irssi_redraw();		// getpass() screws irssi GUI, lets redraw!

		SHA256_memory(iniKey, strlen(iniKey), SHA256digest);
		for(i=0;i<40872;i++) SHA256_memory(SHA256digest, 32, SHA256digest);
		htob64(SHA256digest, B64digest, 32);
		strcpy(iniKey, B64digest);      // this is used for encrypting blow.ini
		for(i=0;i<30752;i++) SHA256_memory(SHA256digest, 32, SHA256digest);
		htob64(SHA256digest, B64digest, 32);	// this is used to verify the entered password
		if(strcmp(B64digest, iniPasswordHash) != 0)
		{
			printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Wrong blow.ini password entered, try again...");
			printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH module NOT loaded.\002");
			return;
		}
		printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Correct blow.ini password entered, lets go!");
	}
	else
	{
		strcpy(iniKey, default_iniKey);
		printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Using default password to decrypt blow.ini... Try /setinipw to set a custom password.");
	}


	signal_add_first("server sendmsg", (SIGNAL_FUNC) encrypt_msg);
	signal_add_first("message private", (SIGNAL_FUNC) decrypt_msg);
	signal_add_first("message public", (SIGNAL_FUNC) decrypt_msg);
	signal_add_first("message irc notice", (SIGNAL_FUNC) decrypt_notice);
	signal_add_first("message irc action", (SIGNAL_FUNC) decrypt_action);

	signal_add_first("message own_private", (SIGNAL_FUNC) format_msg);
	signal_add_first("message own_public", (SIGNAL_FUNC) format_msg);

	signal_add_first("channel topic changed", (SIGNAL_FUNC) decrypt_changed_topic);
	signal_add_first("message topic", (SIGNAL_FUNC) decrypt_topic);
	signal_add_first("server incoming", (SIGNAL_FUNC) raw_handler);

	signal_add("query created", (SIGNAL_FUNC) do_auto_keyx);
	signal_add("query nick changed", (SIGNAL_FUNC) query_nick_changed);

	command_bind("topic+", NULL, (SIGNAL_FUNC) cmd_crypt_TOPIC);
	command_bind("notice+", NULL, (SIGNAL_FUNC) cmd_crypt_notice);
	command_bind("notfish", NULL, (SIGNAL_FUNC) cmd_crypt_notice);
	command_bind("me+", NULL, (SIGNAL_FUNC) cmd_crypt_action);
	command_bind("setkey", NULL, (SIGNAL_FUNC) cmd_setkey);
	command_bind("delkey", NULL, (SIGNAL_FUNC) cmd_delkey);
	command_bind("key", NULL, (SIGNAL_FUNC) cmd_key);
	command_bind("showkey", NULL, (SIGNAL_FUNC) cmd_key);
	command_bind("keyx", NULL, (SIGNAL_FUNC) cmd_keyx);
	command_bind("setinipw", NULL, (SIGNAL_FUNC) cmd_setinipw);
	command_bind("unsetinipw", NULL, (SIGNAL_FUNC) cmd_unsetinipw);

	command_bind("fishhelp", NULL, (SIGNAL_FUNC) cmd_helpfish);
	command_bind("helpfish", NULL, (SIGNAL_FUNC) cmd_helpfish);

	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		"FiSH v1.00 - encryption module for irssi loaded! URL: http://fish.sekure.us\n"
		"Try /helpfish or /fishhelp for a short command overview");

	module_register("fish", "core");
}



void fish_deinit(void)
{
	signal_remove("server sendmsg", (SIGNAL_FUNC) encrypt_msg);
	signal_remove("message private", (SIGNAL_FUNC) decrypt_msg);
	signal_remove("message public", (SIGNAL_FUNC) decrypt_msg);
	signal_remove("message irc notice", (SIGNAL_FUNC) decrypt_notice);
	signal_remove("message irc action", (SIGNAL_FUNC) decrypt_action);

	signal_remove("message own_private", (SIGNAL_FUNC) format_msg);
	signal_remove("message own_public", (SIGNAL_FUNC) format_msg);

	signal_remove("channel topic changed", (SIGNAL_FUNC) decrypt_changed_topic);
	signal_remove("message topic", (SIGNAL_FUNC) decrypt_topic);
	signal_remove("server incoming", (SIGNAL_FUNC) raw_handler);

	signal_remove("query created", (SIGNAL_FUNC) do_auto_keyx);
	signal_remove("query nick changed", (SIGNAL_FUNC) query_nick_changed);

	command_unbind("topic+", (SIGNAL_FUNC) cmd_crypt_TOPIC);
	command_unbind("notice+", (SIGNAL_FUNC) cmd_crypt_notice);
	command_unbind("notfish", (SIGNAL_FUNC) cmd_crypt_notice);
	command_unbind("me+", (SIGNAL_FUNC) cmd_crypt_action);
	command_unbind("setkey", (SIGNAL_FUNC) cmd_setkey);
	command_unbind("delkey", (SIGNAL_FUNC) cmd_delkey);
	command_unbind("key", (SIGNAL_FUNC) cmd_key);
	command_unbind("showkey", (SIGNAL_FUNC) cmd_key);
	command_unbind("keyx", (SIGNAL_FUNC) cmd_keyx);
	command_unbind("setinipw", (SIGNAL_FUNC) cmd_setinipw);
	command_unbind("unsetinipw", (SIGNAL_FUNC) cmd_unsetinipw);

	command_unbind("fishhelp", (SIGNAL_FUNC) cmd_helpfish);
	command_unbind("helpfish", (SIGNAL_FUNC) cmd_helpfish);

	DH1080_DeInit();
}



// :someone!ident@host.net PRIVMSG leetguy :Some Text -> Result: Rnick="someone"
int ExtractRnick(char *Rnick, char *msg)		// needs direct pointer to "nick@host" or ":nick@host"
{
	int k=0;

	if(*msg==':' || *msg==' ') msg++;

	while(*msg!='!' && *msg!='\0' && *msg!=' ' && k < CONTACT_SIZE)
	{
		Rnick[k]=*msg;
		msg++;
		k++;
	}
	Rnick[k]='\0';

	if (*Rnick != '\0') return TRUE;
	else return FALSE;
}


// replace '[' and ']' from nick/channel with '~' (otherwise problems with .ini files)
void FixIniSection(const char *section, char *fixedSection)
{
	if(section!=NULL)
	{
		strncpy(fixedSection, section, CONTACT_SIZE);
		fixedSection[CONTACT_SIZE-1] = '\0';
	}

	while(*fixedSection != '\0')
	{
		if((*fixedSection == '[') || (*fixedSection == ']')) *fixedSection='~';
		fixedSection++;
	}
}


void memXOR(char *s1, const char *s2, int n)
{
	while(n--) *s1++ ^= *s2++;
}


// removes leading and trailing blanks from string
char *strfcpy(char *dest, char *buffer, int destSize)
{
	int i=0, k=strlen(buffer);

	if(k < 2) return NULL;

	while(buffer[i]==' ') i++;
	while(buffer[k-1]==' ') k--;

	buffer[k]=0;

	strncpy(dest, buffer+i, destSize);
	dest[destSize-1] = '\0';
	return dest;
}


int GetBlowIniSwitch(const char *section, const char *key, const char *default_value)
{
	char ini_value[10];

	GetPrivateProfileString(section, key, default_value, ini_value, sizeof(ini_value), iniPath);
	if(isNoChar(*ini_value)) return 0;
	else return 1;
}


char *IsPlainPrefix(const char *msg)
{
	char plainPrefix[20]="";
	int i;

	GetPrivateProfileString("FiSH", "plain_prefix", "+p ", plainPrefix, sizeof(plainPrefix), iniPath);
	if(*plainPrefix != '\0')
	{
		i=strlen(plainPrefix);
		if(strncasecmp(msg, plainPrefix, i)==0) return (char *)msg+i;
	}

	return NULL;
}
