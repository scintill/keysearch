/* © Torbjörn Pettersson 2007*/

#define __KERNEL__ /* Only needed to enable some kernel-related defines */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/mempool.h>

struct crypt_config
{
   struct dm_dev *dev;
   sector_t start;
   mempool_t *io_pool;
   mempool_t *page_pool;
   /* crypto related data */
   struct crypt_iv_operations *iv_gen_ops;
   char *iv_mode;
   void *iv_gen_private;
   sector_t iv_offset;
   unsigned int iv_size;
   struct crypto_tfm *tfm;
   unsigned int key_size;
   u8 key[0];
} __attribute__ ((packed));

int keysearch(char *mem, int size)
{
   int i,j;
   struct crypt_config *cr;

   for(i = 0; i < (size - sizeof(struct crypt_config)); i++,mem++)
     {
        cr = (struct crypt_config *) mem;

        if(
           (void *) cr->io_pool        > (void *) 0xc0000000 &&
           (void *) cr->tfm            > (void *) 0xc0000000 &&
           (void *) cr->dev            > (void *) 0xc0000000 &&
           (void *) cr->io_pool        > (void *) 0xc0000000 &&
           (void *) cr->page_pool      > (void *) 0xc0000000 &&
           (void *) cr->iv_gen_ops     > (void *) 0xc0000000 &&
           (void *) cr->iv_mode        > (void *) 0xc0000000 &&
           (void *) cr->iv_gen_private > (void *) 0xc0000000 &&
           (cr->key_size == 16 || cr->key_size == 32) &&
           (cr->iv_size  == 16 || cr->iv_size  == 32) &&
           cr->iv_offset == 0
           )
          {
             if(cr->start > 0)
               printf("offset: %ld blocks\n",
                      (unsigned long int ) cr->start);
             printf("keylenght: %d\n",
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
