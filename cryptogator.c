#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include<time.h>

#define MAX_KEY_LENGTH 64
#define GCRY_CIPHER1 GCRY_CIPHER_AES128	// Pick the cipher here
#define GCRY_CIPHER2 GCRY_CIPHER_AES256
#define BLOCK_LENGTH 16
#define ITERATION 100
//#define DEBUG


clock_t begin, end;
double time_spent_encrypt, time_spent_decrypt;
double time_encrypt[100];
double time_decrypt[100];
size_t key_length;
unsigned char *key;		//  32 is key length for aes256 and 16 is key length for aes128
gcry_cipher_hd_t handle;
gcry_md_hd_t hndle;
gcry_sexp_t r_sexp;
FILE *input_file;
FILE *finalRecord_file;
size_t file_size;
gcry_error_t err = 0;
size_t blk_length;
char iv[BLOCK_LENGTH] = "656589";
char *in_buffer;
char *out_buffer;
char *out_buffer_decry;
char *hmac;
char *public_key, *private_key;
char *ciphertext;
char *decrypted;
char *signature;

char *InputFileName;

void AES (int GCRY_CIPHER); 
void HMAC_SHA256 ();
void HMAC_SHA1 ();
void HMAC_MD5 ();
void meanCalculate (double array[], int n);
void medianCalculate (double array[], int n);
void rsa_1024 ();
void rsa_4096 ();
void signature_rsa_4096 ();
gcry_sexp_t sexp_new (const char *str);
char *sexp_string (gcry_sexp_t sexp);
char *encrypt (char *public_key, char *plaintext);
char *decrypt (char *private_key, char *ciphertext);
void generate_key_1024 (char **public_key, char **private_key);
void generate_key_4096 (char **public_key, char **private_key);
char *sign (char *private_key, char *document);
short verify (char *public_key, char *document, char *signature);

int
main (int argc, char *argv[])
{

  /*
   * get the input file from the argrument in read mode
   * 
   * */
  if(argc==1)
  {
	  printf("Please enter the input file");
	  exit(1);
  }
  else
  {
	  
int strsize = 0;
strsize += strlen(argv[1]);
  
 InputFileName=malloc(strsize);
 InputFileName[0] = '\0';;
strcat(InputFileName, argv[1]);
  
  printf("InputFileName: %s\n", InputFileName);
 

	finalRecord_file=fopen ("finalRecordFile.txt", "w");
	fprintf(finalRecord_file,"Input File name is %s\n\n", InputFileName);
	
      //Below function will Encrypt and Decrypt using AES128 algorithm
/*
 * start comment from here for running RSA 1024 and RSA 4096
 * */
 
      printf ("--aes 128 CBC Encryption and Decryption started--- \n");
      AES (GCRY_CIPHER1);
      printf ("---aes 128 CBC Encryption and Decryption Completed---- \n");
      printf ("--aes 256 CBC Encryption and Decryption started-- \n");
      AES (GCRY_CIPHER2);
      printf ("aes 256 CBC Encryption and Decryption Completed \n");
      printf ("HMAC_SHA1 Hash function started \n");
      HMAC_SHA1 ();
      printf ("HMAC_SHA1 Hash function Completed \n");
      printf ("HMAC_MD5 Hash function started \n");
      HMAC_MD5 ();
      HMAC_SHA256 ();
      printf ("HMAC_MD5 Hash function Completed \n");
      printf ("HMAC_SHA256 Hash function started \n");
      HMAC_SHA256 ();
      printf ("HMAC_SHA256 Hash function Completed \n");

      printf ("HMAC_SHA256 _RSA 4096 Signature started \n");
      signature_rsa_4096 ();
      printf ("HMAC_SHA256 _RSA 4096 Signature Completed \n");
 
/*
 * end comment from here for running RSA 1024 and RSA 4096
 * **/	 


// for running rsa please comment all other cryptographic function and uncomment below function and run rsa in isolation one by one	 
	 
 // rsa_1024();
  //rsa_4096 ();
 


printf("\nfinalRecordFile.txt file is recording all the time taken. Please check is for result\n");
fclose(finalRecord_file);
 // fclose (input_file);
  
  exit (0);
 }
}

short
verify (char *public_key, char *document, char *signature)
{
  gcry_error_t error;

  gcry_mpi_t r_mpi;
  if ((error = gcry_mpi_scan (&r_mpi, GCRYMPI_FMT_USG, document, 0, NULL)))
    {
      printf ("Error in gcry_mpi_scan() in encrypt(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_sexp_t data;
  size_t erroff;
  if ((error =
       gcry_sexp_build (&data, &erroff, "(data (flags raw) (value %m))",
			r_mpi)))
    {
      printf ("Error in gcry_sexp_build() in sign() at %ld: %s\nSource: %s\n",
	      erroff, gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_sexp_t sig = sexp_new (signature);

  gcry_sexp_t public_sexp = sexp_new (public_key);
  short good_sig = 1;
  if ((error = gcry_pk_verify (sig, data, public_sexp)))
    {
      if (gcry_err_code (error) != GPG_ERR_BAD_SIGNATURE)
	{
	  printf ("Error in gcry_pk_verify(): %s\nSource: %s\n",
		  gcry_strerror (error), gcry_strsource (error));
	  exit (1);
	}
      good_sig = 0;
    }
  return good_sig;
}

gcry_sexp_t
sexp_new (const char *str)
{
  gcry_error_t error;

  gcry_sexp_t sexp;
  size_t len = strlen (str);
  /*
     below is generic function to create an new S-expression object from its external
     representation in buffer of length bytes. Autodetect set to 1 the parses any of the defined external
     formats.
   */
  if ((error = gcry_sexp_new (&sexp, str, len, 1)))
    {
      printf ("Error in sexp_new(%s): %s\nSource: %s\n", str,
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  return sexp;
}

char *
sexp_string (gcry_sexp_t sexp)
{

  /*
     Copies the S-expression object sexp into buffer using the format specified in mode.
     maxlength must be set to the allocated length of buffer. The function returns the
     actual length of valid bytes put into buffer or 0 if the provided buffer is too short.
     Passing NULL for buffer returns the required length for buffer. For convenience reasons
     an extra byte with value 0 is appended to the buffer
   */

  size_t buf_len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  char *buffer = (char *) gcry_malloc (buf_len);
  if (buffer == NULL)
    {
      printf ("gcry_malloc(%ld) returned NULL in sexp_string()!\n", buf_len);
      exit (1);
    }
  if (0 == gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, buffer, buf_len))
    {
      printf ("gcry_sexp_sprint() lies!\n");
      exit (1);
    }
  return buffer;

  // This should be freed with gcry_free(buffer);
}

char *
encrypt (char *public_key, char *plaintext)
{
  gcry_error_t error;

  gcry_mpi_t r_mpi;
/*
Convert the external representation of an integer stored in buffer with a length of
buflen into a newly created MPI returned which will be stored at the address of
r_mpi.For GCRYMPI_FMT_HEX buflen is not required so passing 0
*/

  if ((error =
       gcry_mpi_scan (&r_mpi, GCRYMPI_FMT_USG, plaintext, strlen (plaintext),
		      NULL)))
    {
      printf ("Error in gcry_mpi_scan() in encrypt(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_sexp_t data;
  size_t erroff;

/*
This function creates an internal S-expression (stored in data )from the string template format and
stores it at the address of r_sexp.
*/

  if ((error =
       gcry_sexp_build (&data, &erroff, "(data (flags raw) (value %m))",
			r_mpi)))
    {
      printf
	("Error in gcry_sexp_build() in encrypt() at %ld: %s\nSource: %s\n",
	 erroff, gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_sexp_t public_sexp = sexp_new (public_key);
  gcry_sexp_t r_ciph;
  if ((error = gcry_pk_encrypt (&r_ciph, data, public_sexp)))
    {
      printf ("Error in gcry_pk_encrypt(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  return sexp_string (r_ciph);
}

char *
decrypt (char *private_key, char *ciphertext)
{
  gcry_error_t error;
  gcry_sexp_t data = sexp_new (ciphertext);

  gcry_sexp_t private_sexp = sexp_new (private_key);
  gcry_sexp_t r_plain;
  if ((error = gcry_pk_decrypt (&r_plain, data, private_sexp)))
    {
      printf ("Error in gcry_pk_decrypt(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_mpi_t r_mpi = gcry_sexp_nth_mpi (r_plain, 0, GCRYMPI_FMT_USG);

  unsigned char *plaintext;
  size_t plaintext_size;
  if ((error =
       gcry_mpi_aprint (GCRYMPI_FMT_USG, &plaintext, &plaintext_size, r_mpi)))
    {
      printf ("Error in gcry_mpi_aprint(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  return plaintext;
}




void
generate_key_1024 (char **public_key, char **private_key)
{
  gcry_error_t error;

  // Generate a reduced strength (to save time) RSA key, 1024 bits long
  gcry_sexp_t params =
    sexp_new ("(genkey (rsa (transient-key) (nbits 4:1024)))");
  gcry_sexp_t r_key;

  /*
   *Below function create a new public key pair using information given in the S-expression
   parms and stores the private and the public key in one new S-expression at the address
   given by r_key.
   */

  if ((error = gcry_pk_genkey (&r_key, params)))
    {
      printf ("Error in gcry_pk_genkey(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_sexp_t public_sexp = gcry_sexp_nth (r_key, 1);
  gcry_sexp_t private_sexp = gcry_sexp_nth (r_key, 2);

  *public_key = sexp_string (public_sexp);
  *private_key = sexp_string (private_sexp);
}

void
generate_key_4096 (char **public_key, char **private_key)
{
  gcry_error_t error;

  // Generate a reduced strength (to save time) RSA key, 1024 bits long
  gcry_sexp_t params =
    sexp_new ("(genkey (rsa (transient-key) (nbits 4:4096)))");
  gcry_sexp_t r_key;

  /*
   *Below function create a new public key pair using information given in the S-expression
   parms and stores the private and the public key in one new S-expression at the address
   given by r_key.
   */

  if ((error = gcry_pk_genkey (&r_key, params)))
    {
      printf ("Error in gcry_pk_genkey(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_sexp_t public_sexp = gcry_sexp_nth (r_key, 1);
  gcry_sexp_t private_sexp = gcry_sexp_nth (r_key, 2);

  *public_key = sexp_string (public_sexp);
  *private_key = sexp_string (private_sexp);
}

char *
sign (char *private_key, char *document)
{
  gcry_error_t error;

  gcry_mpi_t r_mpi;
  if ((error = gcry_mpi_scan (&r_mpi, GCRYMPI_FMT_USG, document, 0, NULL)))
    {
      printf ("Error in gcry_mpi_scan() in encrypt(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_sexp_t data;
  size_t erroff;
  if ((error =
       gcry_sexp_build (&data, &erroff, "(data (flags raw) (value %m))",
			r_mpi)))
    {
      printf ("Error in gcry_sexp_build() in sign() at %ld: %s\nSource: %s\n",
	      erroff, gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  gcry_sexp_t private_sexp = sexp_new (private_key);
  gcry_sexp_t r_sig;
  if ((error = gcry_pk_sign (&r_sig, data, private_sexp)))
    {
      printf ("Error in gcry_pk_sign(): %s\nSource: %s\n",
	      gcry_strerror (error), gcry_strsource (error));
      exit (1);
    }

  return sexp_string (r_sig);
}

void
signature_rsa_4096 ()
{ 
   
  input_file = fopen (InputFileName, "r");
  /*Get filesize in bytes */
  fseek (input_file, 0, SEEK_END);
  file_size = ftell (input_file);	//long int ftell(FILE *stream) returns the current file position of the given stream.
  fseek (input_file, 0L, SEEK_SET);

   FILE *out_file;
  in_buffer = (char *) malloc (file_size);
  size_t encrypted_bytes =
    fread (in_buffer, sizeof (char), file_size, input_file); 
      out_file = fopen ("DigitalSignature.txt", "w");
      out_buffer = (char *) malloc (file_size);
      key = (unsigned char *) malloc (MAX_KEY_LENGTH);

// generate randon number for the key
      gcry_randomize (key, MAX_KEY_LENGTH * sizeof (unsigned char),
		      GCRY_STRONG_RANDOM);

      gcry_md_open (&hndle, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
      gcry_md_setkey (hndle, key, MAX_KEY_LENGTH * sizeof (char));    
  		
	/*generate the hash of the buffer data*/
      gcry_md_write (hndle, out_buffer, encrypted_bytes);
      gcry_md_final (hndle);
      hmac = gcry_md_read (hndle, GCRY_MD_SHA256); 
      free (in_buffer);
      gcry_md_close (hndle);     

	  generate_key_4096 (&public_key, &private_key);
	  signature = sign (private_key, hmac);
    
      begin=clock();
      
      fwrite (signature, sizeof (char), strlen (signature),out_file); 
      end=clock();
      
      double time_spent = (double) (end - begin) / CLOCKS_PER_SEC * 1000;
          
      fclose(out_file); 
     fputs("---Digital signature using HMAC 256 and RSA 4096-----\n",finalRecord_file);
     
      fprintf (finalRecord_file,"Time spend (in Milli sec) is %.4f\n", time_spent);
  
	  if (verify (public_key, hmac, signature))
		{
		  fputs ("Signature GOOD!\n",finalRecord_file);
		}
	  else
		{
		   fputs ("Signature BAD!\n",finalRecord_file);
		}
		
		  if(input_file==NULL)
  {
	 
	  input_file = fopen (InputFileName, "r");
  }  
  fclose(input_file);
}

void
rsa_1024 ()
{

 
  input_file = fopen (InputFileName, "r");
  /*Get filesize in bytes */
  fseek (input_file, 0, SEEK_END);
  file_size = ftell (input_file);	//long int ftell(FILE *stream) returns the current file position of the given stream.
  fseek (input_file, 0L, SEEK_SET);

  FILE *out_file;
  FILE *out_fle; 


/*
 * RSA1024 Encryption for 100 Iteration. In each Iteration we will Encrypt the data and the Decrypt it.
 * After Encryption we will store in RSA1024_Encrpy.txt file and after decryption it will store the output in RSA1024_Decrpy.txt file
 * */
  int i, j;
  for (i = 0; i < ITERATION; i++)
    {
      out_file = fopen ("RSA1024_Encrpy.txt", "w+");
      out_fle = fopen ("RSA1024_Decrpy.txt", "w");
      generate_key_1024 (&public_key, &private_key);
	 
      char tempBlock[BLOCK_LENGTH] = { 0 };
      time_spent_encrypt = 0.0;
      double temp_time = 0.0;
	 
	if(input_file==NULL)
	{
		  
		 input_file = fopen (InputFileName, "r");
	}
	// set the inputfile to the starting for each iteration
	fseek (input_file, 0L, SEEK_SET);
	
      while (!feof (input_file))
	{
	  int bytes =
	    fread (tempBlock, sizeof (char), BLOCK_LENGTH, input_file);
	  
	  begin = clock ();
	  ciphertext = encrypt (public_key, tempBlock);
	  end = clock ();
	   
	  if (out_file)
	    fwrite (ciphertext, sizeof (char), strlen (ciphertext), out_file);
	  memset (tempBlock, 0x0, BLOCK_LENGTH);
	  temp_time = (double) (end - begin) / CLOCKS_PER_SEC * 1000;
	  time_spent_encrypt = time_spent_encrypt + temp_time;
	  

	}
	fclose(out_file);
 
	
	out_file=fopen("RSA1024_Encrpy.txt","r");
	fseek (out_file, 0L, SEEK_SET);
	 
      time_encrypt[i] = time_spent_encrypt;
    
      /*
       * RSA1024 Decryption
       * */
      char *line = NULL;
      size_t len = 0;
      ssize_t read;
      int counter = 1;
      char finalString[350];
      time_spent_decrypt = 0.0;
      double temp_timeD = 0.0;
       
     
      
      while ((read = getline (&line, &len, out_file)) != -1)
	{
	
	 
	  strcat (finalString, line);
	 
	  counter++;
	  if (counter == 6)
	    {
	      begin = clock ();
	      
	      decrypted = decrypt (private_key, finalString);
	      end = clock ();
	      temp_timeD =
		(double) (end - begin) / CLOCKS_PER_SEC * 1000;
		 
	      time_spent_decrypt = time_spent_decrypt + temp_timeD;                                  
	      fwrite (decrypted, sizeof (char), strlen (decrypted) - 1,
		      out_fle);
	     
	     
	     finalString[0]=0;
	   
	      counter = 1;
	       
	    }
	}
 
      time_decrypt[i] = time_spent_decrypt;
  }
      fclose (out_file);
      fclose (out_fle);   
      
  fputs ("----RSA 1024 ENCRYPTION DETAILS----\n",finalRecord_file);
  fputs ("Mean time Encryption (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_encrypt, ITERATION);
  fputs ("Median of Encryption (in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_encrypt, ITERATION);
  fputs ("Mean of Decryption (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_decrypt, ITERATION);
  fputs ("Median of Decryption(in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_decrypt, ITERATION);  
  
    if(input_file==NULL)
  {
	    input_file = fopen (InputFileName, "r");
  }  
  fclose(input_file);

   }

void
rsa_4096 ()
{
  
  input_file = fopen (InputFileName, "r");
  /*Get filesize in bytes */
  fseek (input_file, 0, SEEK_END);
  file_size = ftell (input_file);	//long int ftell(FILE *stream) returns the current file position of the given stream.
  fseek (input_file, 0L, SEEK_SET);

  FILE *out_file;
  FILE *out_fle; 


/*
 * 4096  Encryption for several Iteration. In each Iteration we will Encrypt the data and the Decrypt it.
 * After Encryption we will store in RSA4096_Encrpy.txt file and after decryption it will store the output in RSA4096_Decrpy.txt file
 * */
  int i, j;
  for (i = 0; i < ITERATION; i++)
    {
      out_file = fopen ("RSA4096_Encrpy.txt", "w+");
      out_fle = fopen ("RSA4096_Decrpy.txt", "w");
      generate_key_4096 (&public_key, &private_key);
		  
      char tempBlock[BLOCK_LENGTH] = { 0 };
      time_spent_encrypt = 0.0;
      double temp_time = 0.0;
	 
	if(input_file==NULL)
	{
		 
		 input_file = fopen (InputFileName, "r");
	}
	// set the inputfile to the starting for each iteration
	fseek (input_file, 0L, SEEK_SET);
	
      while (!feof (input_file))
	{
	  int bytes =
	    fread (tempBlock, sizeof (char), BLOCK_LENGTH, input_file);
	   
	  begin = clock ();
	  ciphertext = encrypt (public_key, tempBlock);
	  end = clock ();
	  
	  if (out_file)
	    fwrite (ciphertext, sizeof (char), strlen (ciphertext), out_file);
	  memset (tempBlock, 0x0, BLOCK_LENGTH);
	  temp_time = (double) (end - begin) / CLOCKS_PER_SEC * 1000;
	  time_spent_encrypt = time_spent_encrypt + temp_time;
	  
	}
	fclose(out_file);	
	out_file=fopen("RSA4096_Encrpy.txt","r");
	fseek (out_file, 0L, SEEK_SET);
	 
      time_encrypt[i] = time_spent_encrypt;
     
      /*
       * RSA4096 Decryption
       * */
      char *line = NULL;
      size_t len = 0;
      ssize_t read;
      int counter = 1;
      char finalString[1050]; // each encrypted file is 1046B approx so taking finalString as 1050Byte
      time_spent_decrypt = 0.0;
      double temp_timeD = 0.0;
       
       //if(out_file==NULL)
      // {
		   
      // fseek (out_file, 0L, SEEK_SET);
       
      
      while ((read = getline (&line, &len, out_file)) != -1)
	{
	
	 
	  strcat (finalString, line);
	  
	  counter++;
	  if (counter == 6)
	    {
	      begin = clock ();
	      
	      decrypted = decrypt (private_key, finalString);
	      end = clock ();
	      temp_timeD =
		(double) (end - begin) / CLOCKS_PER_SEC * 1000;
		 
	      time_spent_decrypt = time_spent_decrypt + temp_timeD;                                  
	      fwrite (decrypted, sizeof (char), strlen (decrypted) - 1,
		      out_fle); 
	     finalString[0]=0;	    
	      counter = 1;	       
	    }
	}
	 
      time_decrypt[i] = time_spent_decrypt;
  }
      fclose (out_file);
      fclose (out_fle);   
      
  fputs ("----RSA 4096 ENCRYPTION DETAILS----\n",finalRecord_file);
  fputs ("Mean time Encryption (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_encrypt, ITERATION);
  fputs ("Median of Encryption (in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_encrypt, ITERATION);
  fputs ("Mean of Decryption (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_decrypt, ITERATION);
  fputs ("Median of Decryption(in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_decrypt, ITERATION);  
  
    if(input_file==NULL)
  {
	    printf("input fot null");
	    input_file = fopen (InputFileName, "r");
  }  
  fclose(input_file);
  }
 

void
HMAC_SHA256 ()
{
 
  input_file = fopen (InputFileName, "r");
  /*Get filesize in bytes */
  fseek (input_file, 0, SEEK_END);
  file_size = ftell (input_file);	//long int ftell(FILE *stream) returns the current file position of the given stream.
  fseek (input_file, 0L, SEEK_SET);
	
  int i = 0;
   FILE *out_file;
  in_buffer = (char *) malloc (file_size);
  size_t encrypted_bytes =
    fread (in_buffer, sizeof (char), file_size, input_file);

  for (i = 0; i < ITERATION; i++)
    {
      out_file = fopen ("HMAC_SHA256_HashValue.txt", "w");
      out_buffer = (char *) malloc (file_size);
      key = (unsigned char *) malloc (MAX_KEY_LENGTH);

// generate randon number for the key
      gcry_randomize (key, MAX_KEY_LENGTH * sizeof (unsigned char),
		      GCRY_STRONG_RANDOM);

      gcry_md_open (&hndle, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
      gcry_md_setkey (hndle, key, MAX_KEY_LENGTH * sizeof (char));    

      begin = clock ();
		
	/*generate the hash of the buffer data*/
      gcry_md_write (hndle, out_buffer, encrypted_bytes);
      gcry_md_final (hndle);
      hmac = gcry_md_read (hndle, GCRY_MD_SHA256);
      end = clock ();
      time_spent_encrypt = (double) (end - begin) / CLOCKS_PER_SEC * 1000;	// using the 
      time_encrypt[i] = time_spent_encrypt; 
      fwrite (hmac, sizeof (char), strlen (hmac),out_file);
      
      /* int index;
      printf ("Hash_buffer = ");
      for (index = 0; index < file_size; index++)
	printf ("%02X", (unsigned char) hmac[index]);
      printf ("\n");
      // printf ("%s\n", hmac);*/
      
      free (out_buffer);
      fclose(out_file);
      gcry_md_close (hndle);
    } 
  fputs ("----HMAC SHA 256  ENCRYPTION DETAILS----\n",finalRecord_file);
  fputs ("Mean time of Hashing (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_encrypt, ITERATION);
  fputs ("Median time of Hashing (in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_encrypt, ITERATION);  
   if(input_file==NULL)
  {
	   
	  input_file = fopen (InputFileName, "r");
  }  
  fclose(input_file);
    
}
 
void HMAC_MD5 ()
{
  
  input_file = fopen (InputFileName, "r");
  /*Get filesize in bytes */
  fseek (input_file, 0, SEEK_END);
  file_size = ftell (input_file);	//long int ftell(FILE *stream) returns the current file position of the given stream.
  fseek (input_file, 0L, SEEK_SET);
  
  int i = 0;
   FILE *out_file;
  in_buffer = (char *) malloc (file_size);
  size_t encrypted_bytes =
    fread (in_buffer, sizeof (char), file_size, input_file);

  for (i = 0; i < ITERATION; i++)
    {
      out_file = fopen ("HMAC_SHA_MD5_HashValue.txt", "w");
      out_buffer = (char *) malloc (file_size);
      key = (unsigned char *) malloc (MAX_KEY_LENGTH);

// generate randon number for the key
      gcry_randomize (key, MAX_KEY_LENGTH * sizeof (unsigned char),
		      GCRY_STRONG_RANDOM);

      gcry_md_open (&hndle, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
      gcry_md_setkey (hndle, key, MAX_KEY_LENGTH * sizeof (char));    

      begin = clock ();
		
	/*generate the hash of the buffer data*/
      gcry_md_write (hndle, out_buffer, encrypted_bytes);
      gcry_md_final (hndle);
      hmac = gcry_md_read (hndle, GCRY_MD_MD5);
      end = clock ();
      time_spent_encrypt = (double) (end - begin) / CLOCKS_PER_SEC * 1000;	// using the 
      time_encrypt[i] = time_spent_encrypt; 
      fwrite (hmac, sizeof (char), strlen (hmac),out_file);
      
      /* int index;
      printf ("Hash_buffer = ");
      for (index = 0; index < file_size; index++)
	printf ("%02X", (unsigned char) hmac[index]);
      printf ("\n");
      // printf ("%s\n", hmac);*/
      
      free (out_buffer);
      fclose(out_file);
      gcry_md_close (hndle);
    } 
  fputs ("----HMAC SHA MD5 ENCRYPTION DETAILS----\n",finalRecord_file);
  fputs ("Mean time of Hashing (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_encrypt, ITERATION);
  fputs ("Median time of Hashing (in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_encrypt, ITERATION);    
   if(input_file==NULL)
  {
	  input_file = fopen (InputFileName, "r");
  }  
  fclose(input_file);
}

void
HMAC_SHA1 ()
{ 
  input_file = fopen (InputFileName, "r");
  /*Get filesize in bytes */
  fseek (input_file, 0, SEEK_END);
  file_size = ftell (input_file);	//long int ftell(FILE *stream) returns the current file position of the given stream.
  fseek (input_file, 0L, SEEK_SET);

	
	
  int i = 0;
   FILE *out_file;
  in_buffer = (char *) malloc (file_size);
  size_t encrypted_bytes =
    fread (in_buffer, sizeof (char), file_size, input_file);

  for (i = 0; i < ITERATION; i++)
    {
      out_file = fopen ("HMAC_SHA1_HashValue.txt", "w");
      out_buffer = (char *) malloc (file_size);
      key = (unsigned char *) malloc (MAX_KEY_LENGTH);

// generate randon number for the key
      gcry_randomize (key, MAX_KEY_LENGTH * sizeof (unsigned char),
		      GCRY_STRONG_RANDOM);

      gcry_md_open (&hndle, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
      gcry_md_setkey (hndle, key, MAX_KEY_LENGTH * sizeof (char));    

      begin = clock ();
		
	/*generate the hash of the buffer data*/
      gcry_md_write (hndle, out_buffer, encrypted_bytes);
      gcry_md_final (hndle);
      hmac = gcry_md_read (hndle, GCRY_MD_SHA1);
      end = clock ();
      time_spent_encrypt = (double) (end - begin) / CLOCKS_PER_SEC * 1000;	
      time_encrypt[i] = time_spent_encrypt; 
      fwrite (hmac, sizeof (char), strlen (hmac),out_file);
      
      /* int index;
      printf ("Hash_buffer = ");
      for (index = 0; index < file_size; index++)
	printf ("%02X", (unsigned char) hmac[index]);
      printf ("\n");
      // printf ("%s\n", hmac);*/
      
      free (out_buffer);
      fclose(out_file);
      gcry_md_close (hndle);
    } 
  fputs ("----HMAC SHA1  ENCRYPTION DETAILS----\n",finalRecord_file);
  fputs ("Mean time of Hashing (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_encrypt, ITERATION);
  fputs ("Median time of Hashing (in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_encrypt, ITERATION);    
  
   if(input_file==NULL)
  {
	    input_file = fopen (InputFileName, "r");
  }  
  fclose(input_file);
}


void
AES (int GCRY_CIPHER)
{
   /*opening the input file");**/
  input_file = fopen (InputFileName, "r");
  /*Get filesize in bytes */
  fseek (input_file, 0, SEEK_END);
  file_size = ftell (input_file);	//long int ftell(FILE *stream) returns the current file position of the given stream.
  fseek (input_file, 0L, SEEK_SET);

	
  int i, j;
  key_length = gcry_cipher_get_algo_keylen (GCRY_CIPHER);
  blk_length = gcry_cipher_get_algo_blklen (GCRY_CIPHER);

  /*
   * below files are used for storing Encrypted content and decrypted content
   * */

  FILE *out_Encryptfile;
  FILE *out_Decryptfle;

  in_buffer = (char *) malloc (file_size);
  
  size_t encrypted_bytes =
    fread (in_buffer, sizeof (char), file_size, input_file);

  for (i = 0; i < ITERATION; i++)
    {

      if (GCRY_CIPHER == GCRY_CIPHER_AES128)
	{
	  out_Encryptfile = fopen ("AES128_Encrpy.txt", "w");
	  out_Decryptfle = fopen ("AES128_Decrpy.txt", "w");
	}
      else if (GCRY_CIPHER == GCRY_CIPHER_AES256)
	{
	  out_Encryptfile = fopen ("AES256_Encrpy.txt", "w");
	  out_Decryptfle = fopen ("AES256_Decrpy.txt", "w");	   
	}


// dynamically allocate memory for key
      key = (unsigned char *) malloc (key_length);
      //   in_buffer = (char *) malloc (file_size);
      out_buffer = (char *) malloc (file_size);
      out_buffer_decry = (char *) malloc (file_size);

// generate randon number for the key
      gcry_randomize (key, key_length * sizeof (unsigned char),
		      GCRY_STRONG_RANDOM);

if (GCRY_CIPHER == GCRY_CIPHER_AES128)
{
	/*open encryption and set the keys*/
      gcry_cipher_open (&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC,
			GCRY_CIPHER_CBC_CTS);
      gcry_cipher_setkey (handle, key, key_length * sizeof (char));
}
else if (GCRY_CIPHER == GCRY_CIPHER_AES256)
{
	/*open encryption and set the keys*/
      gcry_cipher_open (&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC,
			GCRY_CIPHER_CBC_CTS);
      gcry_cipher_setkey (handle, key, key_length * sizeof (char));
}
 
/*read in the file into a buffer*/

      /*set the initializtion vector and encrypt the file buffer and display an error if any */
      gcry_cipher_setiv (handle, &iv[0], blk_length);

// start measurining the encryption time
      begin = clock ();
      err =
	gcry_cipher_encrypt (handle, out_buffer, file_size, in_buffer,
			     encrypted_bytes);
      if (!err == GPG_ERR_NO_ERROR)
	{
	  fprintf (stderr, "Failure: %s/%s\n", gcry_strsource (err),
		   gcry_strerror (err));
	  exit (-1);
	}
      end = clock ();
      fwrite (out_buffer, sizeof (char), strlen (out_buffer),
	      out_Encryptfile);
      time_spent_encrypt =
	(double) (end - begin) / CLOCKS_PER_SEC * 1000;      
      time_encrypt[i] = time_spent_encrypt;

// Encrption done 

//start Decryption

/*set the initializtion vector and decrypt the encypted buffer and display an error if any */
      gcry_cipher_setiv (handle, &iv[0], blk_length);
      begin = clock ();
      err =
	gcry_cipher_decrypt (handle, out_buffer_decry, file_size,
			     out_buffer, encrypted_bytes);
      if (!err == GPG_ERR_NO_ERROR)
	{
	  fprintf (stderr, "Failure: %s/%s\n", gcry_strsource (err),
		   gcry_strerror (err));
	  exit (-1);
	}
      fwrite (out_buffer_decry, sizeof (char), strlen (out_buffer_decry),
	      out_Decryptfle);

      end = clock ();
      time_spent_decrypt =
	(double) (end - begin) / CLOCKS_PER_SEC * 1000;
      time_decrypt[i] = time_spent_decrypt;
      gcry_cipher_close (handle);
      free (out_buffer_decry);
      free (out_buffer);
      free (key);
      fclose (out_Decryptfle);
      fclose (out_Encryptfile);
    }

  free (in_buffer);

  if (GCRY_CIPHER == GCRY_CIPHER_AES128)
    {
      fputs ("----AES 128 ENCRYPTION DETAILS----\n",finalRecord_file);
    }
  else if (GCRY_CIPHER == GCRY_CIPHER_AES256)
    {
      fputs ("----AES 256 ENCRYPTION DETAILS----\n",finalRecord_file);
    }
 
  fputs("Mean time Encryption (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_encrypt, ITERATION);
  fputs ("Median of Encryption (in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_encrypt, ITERATION);
  fputs ("Mean of Decryption (in Milli Secs)\n",finalRecord_file);
  meanCalculate (time_decrypt, ITERATION);
  fputs ("Median of Decryption(in Milli Secs)\n",finalRecord_file);
  medianCalculate (time_decrypt, ITERATION);
  
  if(input_file==NULL)
  {
	   input_file = fopen (InputFileName, "r");
  }  
/*close the input file*/
  fclose(input_file);
}

/*close the file and encryption handles*/


void
meanCalculate (double array[], int n)
{
  int x, c;
  float average = 0.0000;
  for (x = 0; x < n; x++)
    {
      average += array[x];

    }

  fprintf (finalRecord_file,"%.4f\n", average / n);
}

void
medianCalculate (double array[], int n)
{
  double temp;
  int i, j;
  float median = 0.0;
 
  // the following two loops sort the array x in ascending order
  for (i = 0; i < n - 1; i++)
    {
      for (j = i + 1; j < n; j++)
	{
	  if (array[j] < array[i])
	    {
	      // swap elements
	      temp = array[i];
	      array[i] = array[j];
	      array[j] = temp;
	    }
	}
    }
       
  if (n % 2 == 0)
    {
      // if there is an even number of elements, return mean of the two elements in the middle
      median = (array[n / 2] + array[n / 2 - 1]) / 2.0;
      
  fprintf (finalRecord_file,"%.4f\n", median);
      
    }
  else
    {
       
      median = array[n / 2];
        fprintf (finalRecord_file,"%.4f\n", median);
       
    }
}

