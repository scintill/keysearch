/* © Torbjörn Pettersson 2007*/

#define __KERNEL__ /* Only needed to enable some kernel-related defines */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct crypt_config
{
   struct dm_dev *dev;
   void *start;
   void *io_pool;
   void *req_pool;
   void *page_pool;
   void *bs;

   void *io_queue;
   void *crypt_queue;

   /* crypto related data */
   char *cipher;
   char *cipher_mode;

   struct crypt_iv_operations *iv_gen_ops;
   union {
       struct {
           void *tfm;
           void *hash_tfm;
           unsigned char *salt;
       } essiv;
       struct {
           int shift;
       } benbi;
   } iv_gen_private;
   void *iv_offset;
   unsigned int iv_size;

   unsigned int dmreq_start;
   void *req;

   struct crypto_tfm *tfm;
   unsigned long flags;
   unsigned int key_size;
   unsigned char key[0];
} __attribute__ ((packed));

int keysearch(char *mem, int size)
{
   int i,j;
   struct crypt_config *cr;

   for(i = 0; i < (size - sizeof(struct crypt_config)); i++,mem++)
     {
        cr = (struct crypt_config *) mem;

        if(
           //(void *) cr->dev            > (void *) 0xc0000000 &&
           (void *) cr->start          > (void *) 0xc0000000 &&
           (void *) cr->io_pool        > (void *) 0xc0000000 &&
           (void *) cr->req_pool       > (void *) 0xc0000000 &&
           (void *) cr->page_pool      > (void *) 0xc0000000 &&
           (void *) cr->bs             > (void *) 0xc0000000 &&
           (void *) cr->io_queue       > (void *) 0xc0000000 &&
           (void *) cr->crypt_queue    > (void *) 0xc0000000 &&
           (void *) cr->cipher         > (void *) 0xc0000000 &&
           (void *) cr->cipher_mode    > (void *) 0xc0000000 &&
           ((void *) cr->iv_gen_private.essiv.tfm < (void *) 0xc0000000
             || ((void *) cr->iv_gen_private.essiv.hash_tfm > (void *) 0xc0000000 &&
                 (void *) cr->iv_gen_private.essiv.salt     > (void *) 0xc0000000)) &&
           cr->iv_offset == 0 &&
           (cr->iv_size  == 16 || cr->iv_size  == 32) &&
           (void *) cr->req            > (void *) 0xc0000000 &&
           (void *) cr->tfm            > (void *) 0xc0000000 &&
           (cr->key_size == 16 || cr->key_size == 32 || cr->key_size == 64)
           )
          {
             if(cr->start > 0)
               printf("offset: %lu blocks\n",
                      (unsigned long int ) cr->start);
             printf("keylength: %d\n",
                    (cr->key_size * 8));
             printf("key: ");
             for(j = 0; j < cr->key_size; j++)
               printf("%02X",cr->key[j]);
             printf("\n");
          }
     }
   return(0);
}

int main(int argc, char **argv)
{
   int fd;
   char *mem = NULL;
   struct stat st;

   if(argc < 2)
     {
        printf("Usage: %s [memory dump file]\n",argv[0]);
        exit(-1);
     }

   if(stat(argv[1],&st) == -1)
     {
        perror("stat()");
        printf("Failed to stat %s\n",argv[1]);
        exit(-1);
     }

   fd = open(argv[1],O_RDONLY);
   if(fd == -1)
     {
        perror("open()");
        printf("Failed to open %s\n",argv[1]);
        exit(-1);
     }

   mem = mmap(0,(int)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
   if(mem == ((void *) -1))
     {
        perror("mmap()");
        exit(-1);
     }

   (void)keysearch(mem,(int)st.st_size);
   return(0);
}
