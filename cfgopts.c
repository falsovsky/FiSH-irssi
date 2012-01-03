#include "cfgopts.h"


static unsigned char line[1000], line_bak[1000];


int GetPrivateProfileString(const char *section, const char *key, const char *default_value, char *buffer, int buflen, const char *filepath)
{
	int len=0;
	FILE *file;
	char *fptr, *key_tok, *value_tok;
	unsigned char INIsection[strlen(section)+4];

	file=fopen(filepath, "r");
	if(file==NULL) goto file_error;

	buffer[0]='\0';
	sprintf(INIsection, "[%s]", section);

	do
	{
		fptr=fgets(line, sizeof(line)-2, file);
	}
	while(strncasecmp(line, INIsection, strlen(INIsection)) && !feof(file));

	do
	{
		fptr=fgets(line, sizeof(line)-2, file);
		if(fptr==NULL) break;

		if(*line=='#' || *line==';' || *line=='/' || *line=='[') continue;    // skip comments

		key_tok=strtok(line, "=\n\r");   // get first token (key)
		if(key_tok)
		{
			value_tok=strtok(NULL, "=\n\r"); // get actual value information
			if(!value_tok) continue;
			if(!strcasecmp(key_tok, key))  // got a match?
			{
				snprintf(buffer, buflen, "%s", value_tok);
				break;
			}
		}
	}
	while(fptr!=NULL && *line!='[');

	fclose(file);

	len=strlen(buffer);
	if(*buffer==0x22 && buffer[len-1]==0x22)	// kill ""
	{
		memmove(buffer, buffer+1, len-2);
		buffer[len-2]='\0';
	}

file_error:
	if(len==0) snprintf(buffer, buflen, "%s", default_value);

	return strlen(buffer);
}



int WritePrivateProfileString(const char *section, const char *key, const char *value, const char *filepath)
{
	int section_not_found=1;
	FILE *infile, *outfile;
	char *fptr, *tok;
	unsigned char INIsection[strlen(section)+4];

	sprintf(INIsection, "[%s]", section);

	infile=fopen(filepath, "r");
	if(infile==NULL)
	{	// file not found, creating new now
		if(*value=='\0') return 1;	// nothing to write
		outfile=fopen(filepath, "w");
		if(outfile==NULL) return -1;
		if(fprintf(outfile, "%s\n%s=%s\n", INIsection, key, value) < 0)
		{
			fclose(outfile);
			return -1;
		}
		fclose(outfile);
		return 1;
	}

	outfile=fopen(tempPath,"w");
	if(outfile==NULL)
	{
		fclose(infile);
		return -1;
	}

	do
	{
		fptr=fgets(line, sizeof(line)-2, infile);
		if(fptr)
		{
			if(fprintf(outfile, "%s", line) < 0) goto fprint_error;
			section_not_found=strncasecmp(line, INIsection, strlen(INIsection));
		}
	}
	while(section_not_found && !feof(infile));

	if(feof(infile))
	{
		if(*value)
		{	// if *value==0, we are deleting
			if(section_not_found)
			{
				if(fprintf(outfile,"\n\n%s", INIsection) < 0) goto fprint_error;
			}
			if(fprintf(outfile, "\n%s=%s\n", key, value) < 0) goto fprint_error;
		}
	}
	else
	{
		do
		{
			fptr=fgets(line, sizeof(line)-2, infile);
			if(fptr==NULL)
			{	// eof reached, lets write it
				if(*value)
				{	// if *value==0, we are deleting
					if(fprintf(outfile, "%s=%s\n", key, value) < 0) goto fprint_error;
				}
				break;
			}

			if(*line=='#' || *line=='\r' || *line=='\n' || *line==';' || *line=='/')
			{
				if(fprintf(outfile, "%s", line) < 0) goto fprint_error;
				continue;  // skip comments
			}
			else if(*line=='[')
			{	// new section found, last section was empty
				if(*value)
				{
					if(fprintf(outfile, "%s=%s\n\n", key, value) < 0) goto fprint_error;
				}

				if(fprintf(outfile, "%s", line) < 0) goto fprint_error;
				do
				{	// write the rest of the file
					fptr=fgets(line, sizeof(line)-2, infile);
					if(fptr)
					{
						if(fprintf(outfile, "%s", line) < 0) goto fprint_error;
					}
				}
				while(!feof(infile));
				break;
			}

			strcpy(line_bak, line);
			tok=strtok(line, "=\n\r");  // get first token
			if(tok)
			{
				if(!strcasecmp(tok, key)) // got a match?
				{
					if(*value)
					{
						if(fprintf(outfile, "%s=%s\n", key, value) < 0) goto fprint_error;
					}
					do
					{	// write the rest of the file
						fptr=fgets(line,sizeof(line)-2, infile);
						if(fptr)
						{
							if(fprintf(outfile, "%s", line) < 0) goto fprint_error;
						}
					}
					while(!feof(infile));
					break;
				}
				if(fprintf(outfile, "%s", line_bak) < 0) goto fprint_error;
			}
		}
		while(fptr);
	}

	fclose(infile);
	fclose(outfile);

	if(rename(tempPath, filepath)!=0) return -1;

	return 1;

fprint_error:
	fclose(infile);
	fclose(outfile);
	return -1;
}
